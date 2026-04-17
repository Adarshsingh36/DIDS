"""
Distributed Trust Manager — Determines if components are trustworthy.

In a distributed system, how do we know if a component is behaving correctly or is
compromised/faulty? This is the trust problem.

The trust manager:
1. Tracks trust scores for each component (0.0 = untrusted, 1.0 = fully trusted)
2. Lowers trust when a component reports suspicious activity
3. Gradually recovers trust over time (is better, it can recover)
4. Uses Byzantine Fault Tolerance (voting) so majority opinion matters
5. Can declare a component ISOLATED if it's definitely bad

Real-world analogy: Like a credit score system - if you do bad things, your score drops.
If you behave, your score recovers. We look at multiple sources of information.
"""
from __future__ import annotations
import asyncio
import logging
import time
from typing import Dict, List, Optional, Set

from dids.core.models import Message, MessageType, NodeStatus
from dids.communication.bus import MessageBus

logger = logging.getLogger(__name__)

# Tuning parameters for trust system
TRUST_DECAY_ON_ALERT   = 0.25  # How much trust drops when component is suspected
TRUST_RECOVERY_RATE    = 0.01  # How much trust recovers per second (1% per second)
ISOLATION_THRESHOLD    = 0.30  # Trust < 30% → ISOLATED (lock it out completely)
SUSPECT_THRESHOLD      = 0.60  # Trust < 60% → SUSPECT (monitor closely)
CONSENSUS_TIMEOUT      = 3.0   # Wait 3 seconds for voting to complete
MAJORITY_FRACTION      = 0.51  # Need >50% to confirm suspicion


class DistributedTrustManager:
    """
    Distributed system for determining which components are trustworthy.
    
    Key concept: No single source of truth. Instead, multiple trust managers
    vote on whether a component is trustworthy (Byzantine Fault Tolerance).
    
    Parameters
    ----------
    dtm_id : ID of this trust manager
    peer_dtm_ids : IDs of other trust managers to coordinate with
    bus : The message bus for communication
    """
    def __init__(self, dtm_id: str, peer_dtm_ids: List[str],
                 bus: MessageBus) -> None:
        self.dtm_id       = dtm_id           # This trust manager's ID
        self.peer_ids     = peer_dtm_ids     # Other trust manager IDs
        self._bus         = bus
        self._node_trust:  Dict[str, float]      = {}  # Trust score for each component
        self._node_status: Dict[str, NodeStatus] = {}  # Status (TRUSTED/SUSPECT/ISOLATED/OFFLINE)
        self._last_seen:   Dict[str, float]      = {}  # When we last heard from component
        self._pending_votes: Dict[str, List[bool]] = {}  # Votes on current suspicions
        self._finalize_tasks: Set[asyncio.Task[None]] = set()  # Cleanup of vote rounds
        self._running = False
        self._inbox = bus.register(dtm_id)

    async def start(self) -> None:
        """
        Start the trust manager.
        
        Launches:
        1. Message listening loop (to receive suspicious behavior reports)
        2. Recovery loop (to gradually restore trust over time)
        """
        self._running = True
        logger.info("[%s] started", self.dtm_id)
        asyncio.create_task(self._message_loop())
        asyncio.create_task(self._recovery_loop())

    async def stop(self) -> None:
        """Stop the trust manager and clean up."""
        self._running = False
        # Cancel any ongoing voting rounds
        tasks = list(self._finalize_tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._finalize_tasks.clear()
        self._bus.deregister(self.dtm_id)

    def register_node(self, node_id: str) -> None:
        """
        Register a new component to monitor.
        
        All components start with full trust (1.0) until proven otherwise.
        """
        self._node_trust.setdefault(node_id, 1.0)
        self._node_status.setdefault(node_id, NodeStatus.TRUSTED)
        self._last_seen[node_id] = time.time()

    def get_trust(self, node_id: str) -> float:
        """Get the current trust score for a component (0.0 to 1.0)."""
        return self._node_trust.get(node_id, 1.0)

    def get_status(self, node_id: str) -> NodeStatus:
        """Get the current status (TRUSTED/SUSPECT/ISOLATED/OFFLINE)."""
        return self._node_status.get(node_id, NodeStatus.TRUSTED)

    def trust_summary(self) -> Dict[str, Dict]:
        """Return summary of trust info for all components."""
        return {
            nid: {
                "trust": round(self._node_trust.get(nid, 1.0), 3),
                "status": self._node_status.get(nid, NodeStatus.TRUSTED).name,
            }
            for nid in self._node_trust
        }

    async def _message_loop(self) -> None:
        """Listen for incoming messages about suspicious components."""
        while self._running:
            msg = await self._bus.receive(self.dtm_id, timeout=0.05)
            if msg:
                await self._handle_message(msg)

    async def _recovery_loop(self) -> None:
        """
        Periodically increase trust for components that have been good.
        
        This runs every second and recovers 1% of lost trust for each component.
        """
        while self._running:
            await asyncio.sleep(1.0)
            for node_id in list(self._node_trust.keys()):
                current = self._node_trust[node_id]
                if current < 1.0:
                    # Increase trust back toward 1.0
                    self._node_trust[node_id] = min(1.0, current + TRUST_RECOVERY_RATE)
                    self._update_status(node_id)

    async def _handle_message(self, msg: Message) -> None:
        """Process different types of incoming messages."""
        if msg.msg_type == MessageType.TRUST_VERIFY:
            # Someone is reporting suspicious behavior from a component
            await self._handle_verify_request(msg)
        elif msg.msg_type == MessageType.TRUST_VOTE:
            # Another trust manager is sending a vote
            await self._handle_vote(msg)
        elif msg.msg_type == MessageType.HEARTBEAT:
            # Update last-seen time for this component
            node = msg.sender
            self._last_seen[node] = time.time()
            self.register_node(node)

    async def _handle_verify_request(self, msg: Message) -> None:
        """
        Someone reported that a component might be suspicious.
        
        Start a voting process with other trust managers:
        1. Ask peers: "Do you think this component is suspicious?"
        2. Wait for 3 seconds for responses
        3. Count votes - if majority says yes, lower its trust significantly
        """
        payload = msg.payload or {}
        suspect  = payload.get("source_node", msg.sender)
        alert_id = payload.get("alert_id", "")
        logger.info("[%s] verification request for node '%s'", self.dtm_id, suspect)
        
        # Immediately lower trust a bit
        self._lower_trust(suspect, TRUST_DECAY_ON_ALERT)
        
        # Start voting round
        round_id = f"{alert_id}:{suspect}"
        self._pending_votes[round_id] = []
        
        # Ask all peer trust managers
        for peer in self.peer_ids:
            await self._bus.send_to(
                receiver=peer, sender=self.dtm_id,
                msg_type=MessageType.TRUST_VOTE,
                payload={"round_id": round_id, "suspect": suspect, "phase": "REQUEST"},
            )
        
        # Schedule finalization (count votes after timeout)
        task = asyncio.create_task(self._finalize_consensus(round_id, suspect))
        self._finalize_tasks.add(task)
        task.add_done_callback(self._finalize_tasks.discard)

    async def _handle_vote(self, msg: Message) -> None:
        """Process voting messages from other trust managers."""
        payload  = msg.payload or {}
        phase    = payload.get("phase", "")
        round_id = payload.get("round_id", "")
        suspect  = payload.get("suspect", "")
        
        if phase == "REQUEST":
            # Peer is asking: "Is this component suspicious?"
            # We'll check our current trust for it
            trust = self.get_trust(suspect)
            vote_suspicious = trust < SUSPECT_THRESHOLD
            
            # Send backour vote
            await self._bus.send_to(
                receiver=msg.sender, sender=self.dtm_id,
                msg_type=MessageType.TRUST_VOTE,
                payload={"round_id": round_id, "suspect": suspect,
                         "phase": "VOTE", "vote": vote_suspicious},
            )
        elif phase == "VOTE":
            # Collecting votes from peers
            if round_id in self._pending_votes:
                self._pending_votes[round_id].append(payload.get("vote", False))

    async def _finalize_consensus(self, round_id: str, suspect: str) -> None:
        """
        After 3 seconds of voting, count the votes and decide.
        
        If majority of trust managers voted "suspicious" → lower trust significantly
        Otherwise → the component is probably okay, maybe it was a false alarm
        """
        await asyncio.sleep(CONSENSUS_TIMEOUT)
        
        votes = self._pending_votes.pop(round_id, [])
        if not votes:
            return
        
        positive = sum(1 for v in votes if v)  # Count votes for "suspicious"
        ratio    = positive / len(votes)       # What % voted for suspicious
        
        if ratio >= MAJORITY_FRACTION:
            # Majority consensus: component is suspicious
            logger.warning("[%s] CONSENSUS: node '%s' confirmed suspicious (%.0f%%)",
                           self.dtm_id, suspect, ratio * 100)
            self._lower_trust(suspect, TRUST_DECAY_ON_ALERT * 2)  # Double penalty
        else:
            # Majority thinks it's okay
            logger.info("[%s] consensus: node '%s' cleared", self.dtm_id, suspect)

    def _lower_trust(self, node_id: str, amount: float) -> None:
        """Reduce trust in a component."""
        current = self._node_trust.get(node_id, 1.0)
        self._node_trust[node_id] = max(0.0, current - amount)
        self._update_status(node_id)

    def _update_status(self, node_id: str) -> None:
        """
        Update status based on current trust score.
        
        Trust score → Status mapping:
        - < 30%: ISOLATED (definitely bad)
        - < 60%: SUSPECT (probably bad)
        - >= 60%: TRUSTED (okay)
        """
        score = self._node_trust.get(node_id, 1.0)
        old   = self._node_status.get(node_id, NodeStatus.TRUSTED)
        
        if score <= ISOLATION_THRESHOLD:    new = NodeStatus.ISOLATED
        elif score <= SUSPECT_THRESHOLD:    new = NodeStatus.SUSPECT
        else:                               new = NodeStatus.TRUSTED
        
        if new != old:
            self._node_status[node_id] = new
            logger.info("[%s] node '%s' status: %s → %s",
                        self.dtm_id, node_id, old.name, new.name)
