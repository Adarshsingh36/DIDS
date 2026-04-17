"""
Global Detection Engine — The "CEO" of the security system.

This is the highest level of the hierarchy:
- Individual agents watch single hosts
- Coordinators aggregate reports from their agents
- This GLOBAL ENGINE aggregates reports from ALL coordinators

Its job:
1. Receive aggregated belief vectors from all regional coordinators
2. Combine them to form a system-wide opinion
3. Detect attacks that span multiple regions (distributed attacks)
4. Alert the Trust Manager about suspicious patterns
5. Log all confirmed alerts

Real-world analogy: Like FBI headquarters getting reports from all field offices
and looking for patterns that suggest a major coordinated attack.

CORRELATION_INTERVAL: Every 2 seconds, review all beliefs and look for patterns
DISTRIBUTED_THRESHOLD: Need 50% confidence to call it a distributed attack
MIN_SUBDOMAINS_FOR_DIST: At least 2 different regions must agree to call it distributed
"""

from __future__ import annotations
import asyncio
import logging
import time
from typing import Dict, List, Optional, Tuple

from dids.core.models import (
    AlertRecord, AttackType, BeliefVector,
    Message, MessageType, ThreatLevel,
)
from dids.communication.bus import MessageBus
from dids.inference.bayesian import BayesianInferenceEngine

logger = logging.getLogger(__name__)

CORRELATION_INTERVAL   = 2.0   # Re-analyze beliefs every 2 seconds
DISTRIBUTED_THRESHOLD  = 0.50  # 50% confidence needed
MIN_SUBDOMAINS_FOR_DIST = 2     # At least 2 regions must report same attack


class GlobalDetectionEngine:
    """
    System-wide detection and correlation engine.
    
    This is the top-level analyzer. It:
    - Receives beliefs from all coordinators
    - Combines them using Bayesian math
    - Looks for signs of coordinated/distributed attacks
    - Sends alerts to dashboard
    - Notifies trust manager of suspicious patterns

    Parameters
    ----------
    engine_id       : unique name (e.g. "global_engine")
    trust_manager_id: who to inform about trust issues
    dashboard_id    : who to send alerts to (the display screen)
    bus             : message bus for communication
    """

    def __init__(self, engine_id: str, trust_manager_id: str,
                 dashboard_id: str, bus: MessageBus) -> None:
        self.engine_id        = engine_id            # This engine's name
        self.trust_manager_id = trust_manager_id     # Who handles trust decisions
        self.dashboard_id     = dashboard_id         # Who displays alerts
        self._bus             = bus
        self._inference       = BayesianInferenceEngine()

        self._subdomain_beliefs:  Dict[str, BeliefVector] = {}  # Latest belief per region
        self._global_belief       = BeliefVector(origin_id=engine_id)  # Our system-wide opinion
        self._confirmed_alerts:   List[AlertRecord]       = []  # All alerts we've confirmed
        self._running             = False

        self._inbox = bus.register(engine_id)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """
        Start the global engine.
        
        Launches two background tasks:
        1. _message_loop: Listen for beliefs from coordinators and alerts from agents
        2. _correlation_loop: Every 2 seconds, correlate all beliefs
        """
        self._running = True
        logger.info("[%s] started", self.engine_id)
        asyncio.create_task(self._message_loop())
        asyncio.create_task(self._correlation_loop())

    async def stop(self) -> None:
        """Stop the engine and cleanup."""
        self._running = False
        self._bus.deregister(self.engine_id)

    # ------------------------------------------------------------------
    # Loops - Main work
    # ------------------------------------------------------------------

    async def _message_loop(self) -> None:
        """
        Process incoming messages.
        
        This handles:
        - BELIEF_UPDATE from coordinators (their latest opinion)
        - ALERT from coordinators/agents (confirmed threats)
        """
        while self._running:
            msg = await self._bus.receive(self.engine_id, timeout=0.05)
            if msg:
                await self._handle_message(msg)

    async def _correlation_loop(self) -> None:
        """
        Periodically analyze all beliefs for system-wide patterns.
        
        Every 2 seconds, this:
        1. Combines beliefs from all coordinators
        2. Looks for distributed attacks (multiple regions seeing same threat)
        3. Sends alerts if detected
        
        This is where we spot coordinated cyberattacks.
        """
        while self._running:
            await asyncio.sleep(CORRELATION_INTERVAL)
            await self._run_global_correlation()

    # ------------------------------------------------------------------
    # Message handling
    # ------------------------------------------------------------------

    async def _handle_message(self, msg: Message) -> None:
        """Process incoming messages from coordinators and agents."""
        if msg.msg_type == MessageType.BELIEF_UPDATE:
            # A coordinator is sending its latest belief
            bv: BeliefVector = msg.payload
            self._subdomain_beliefs[msg.sender] = bv
            logger.debug("[%s] belief from %s: max_p=%.2f",
                         self.engine_id, msg.sender, bv.max_probability())

        elif msg.msg_type == MessageType.ALERT:
            # An alert to confirm - pass it along
            alert: AlertRecord = msg.payload
            await self._handle_alert(alert)

    # ------------------------------------------------------------------
    # Global correlation - Main intelligence work
    # ------------------------------------------------------------------

    async def _run_global_correlation(self) -> None:
        """
        Combine all coordinator beliefs and look for distributed attacks.
        
        Example scenario:
        - Coordinator 1 says: "Port scan detected"
        - Coordinator 2 says: "Port scan detected"
        - Coordinator 3 says: "Port scan detected"
        
        Conclusion: Distributed port scan (same attacker hitting multiple regions)
        """
        vectors = list(self._subdomain_beliefs.values())
        if not vectors:
            return

        # Combine all beliefs using Bayesian math
        agg = BayesianInferenceEngine.aggregate_beliefs(vectors)
        self._global_belief = BeliefVector(
            origin_id=self.engine_id,
            beliefs=agg,
            timestamp=time.time(),
        )

        # Check for distributed attacks (pattern across multiple regions)
        distributed = self._detect_distributed_attack()
        if distributed:
            attack_type, prob, involved = distributed
            # Create an alert about the distributed attack
            alert = AlertRecord(
                source_node=self.engine_id,
                attack_type=attack_type,
                probability=prob,
                threat_level=BeliefVector(
                    origin_id=self.engine_id,
                    beliefs={attack_type.value: prob}
                ).threat_level(),
                evidence=["distributed_correlation"],
                involved_ips=involved,
            )
            logger.warning("[%s] DISTRIBUTED ATTACK DETECTED: %s", self.engine_id, alert)
            await self._escalate_alert(alert)

    def _detect_distributed_attack(self) -> Optional[Tuple[AttackType, float, List[str]]]:
        """
        Check if multiple regions are reporting the same attack type.
        
        Algorithm:
        1. For each attack type, count how many regions report it
        2. If 2+ regions report the same attack above threshold → distributed attack
        
        Example: If 3 coordinators all report DDoS (50%+ confidence each),
        we declare a distributed DDoS attack.
        """
        attack_votes: Dict[str, List[float]] = {}

        # Collect votes for each attack type
        for bv in self._subdomain_beliefs.values():
            if bv.max_probability() >= DISTRIBUTED_THRESHOLD:
                dominant = bv.dominant_threat().value
                attack_votes.setdefault(dominant, []).append(bv.max_probability())

        # Check if any attack type got votes from multiple regions
        for attack, probs in attack_votes.items():
            if len(probs) >= MIN_SUBDOMAINS_FOR_DIST:
                # Multiple regions agree on this attack type
                avg_prob = sum(probs) / len(probs)
                return AttackType(attack), avg_prob, []

        return None

    async def _handle_alert(self, alert: AlertRecord) -> None:
        """
        Process an incoming alert.
        
        This:
        1. Records the alert
        2. Notifies the trust manager about the source
        3. Escalates to the dashboard
        """
        self._confirmed_alerts.append(alert)

        # Notify trust manager - this component sent an alert,
        # might be worth checking if it's trustworthy
        await self._bus.send_to(
            receiver=self.trust_manager_id,
            sender=self.engine_id,
            msg_type=MessageType.TRUST_VERIFY,
            payload={"alert_id": alert.alert_id,
                     "source_node": alert.source_node,
                     "threat_level": alert.threat_level.name},
        )
        await self._escalate_alert(alert)

    async def _escalate_alert(self, alert: AlertRecord) -> None:
        """Send an alert to the dashboard (display it to the operator)."""
        await self._bus.send_to(
            receiver=self.dashboard_id,
            sender=self.engine_id,
            msg_type=MessageType.ALERT,
            payload=alert,
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def global_belief(self) -> BeliefVector:
        """Return the system-wide opinion about what's happening."""
        return self._global_belief

    @property
    def confirmed_alerts(self) -> List[AlertRecord]:
        """Return all alerts we've confirmed so far."""
        return list(self._confirmed_alerts)

    @property
    def subdomain_count(self) -> int:
        """How many coordinators are reporting to us?"""
        return len(self._subdomain_beliefs)