"""
Backup Coordinator — A "standby manager" that takes over if the primary fails.

Think of it like an understudy in a play:
- Under normal circumstances, it sits quietly and watches
- It receives a copy of all the primary coordinator's state every 3 seconds
- If the primary coordinator crashes or becomes unresponsive:
  1. The backup springs into action
  2. It takes over all the primary's responsibilities
  3. It tells all agents "I'm your new coordinator, report to me"
  4. It continues the work seamlessly

This provides HIGH AVAILABILITY - the system keeps running even if one
coordinator fails. Users don't notice any interruption.

HOW IT WORKS:
- STANDBY MODE: Listens silently, receives periodic state copies
- ACTIVE MODE: Fully operates when activated by HealthMonitor
- State is synced every 3 seconds from primary to backup
- If primary hasn't sent heartbeat in 15 seconds, considered dead
"""

from __future__ import annotations
import asyncio
import logging
import time
from typing import Dict, List, Optional

from dids.core.models import (
    AlertRecord, BeliefVector, Message, MessageType,
)
from dids.communication.bus import MessageBus
from dids.inference.bayesian import BayesianInferenceEngine

logger = logging.getLogger(__name__)

SYNC_INTERVAL      = 3.0    # State sync from primary every 3 seconds
HEARTBEAT_TIMEOUT  = 15.0   # Agent is dead if no heartbeat for 15 seconds


class BackupCoordinator:
    """
    Hot-standby backup for a SubdomainCoordinator.
    
    TERMINOLOGY:
    - "Hot-standby" means it's always running (warm) and ready to take over instantly
    - "Mirror" means it keeps a copy of the primary's state
    - "Failover" means switching from primary to backup when primary fails

    Parameters
    ----------
    backup_id        : This backup's name (e.g. "coord_g0_backup")
    primary_id       : Which coordinator this backs up (e.g. "coord_g0")
    global_engine_id : Where to send reports when we're active
    agent_ids        : List of agents we manage (used to redirect them if we activate)
    bus              : Message bus for communication
    """

    def __init__(self, backup_id: str, primary_id: str,
                 global_engine_id: str, agent_ids: List[str],
                 bus: MessageBus) -> None:
        self.backup_id        = backup_id
        self.primary_id       = primary_id
        self.global_engine_id = global_engine_id
        self.agent_ids        = agent_ids
        self._bus             = bus
        self._engine          = BayesianInferenceEngine()

        self._active            = False         # False = standby, True = active
        self._agent_beliefs:    Dict[str, BeliefVector] = {}
        self._agent_last_seen:  Dict[str, float]        = {}
        self._aggregated_belief = BeliefVector(origin_id=backup_id)
        self._alerts:           List[AlertRecord]       = []
        self._running           = False

        self._inbox = bus.register(backup_id)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        self._running = True
        logger.info("[%s] started (STANDBY) — mirroring %s",
                    self.backup_id, self.primary_id)
        asyncio.create_task(self._message_loop())

    async def stop(self) -> None:
        self._running = False
        self._bus.deregister(self.backup_id)

    # ── Failover activation ───────────────────────────────────────────────────

    async def activate(self, reason: str = "primary_failure") -> None:
        """
        Called by HealthMonitor when primary is declared dead.
        
        This is the moment we transition from "standby" to "active".
        We:
        1. Set ourselves to ACTIVE mode
        2. Tell all our agents "I'm your new coordinator!"
        3. Start the aggregation loop to begin normal coordinator work
        
        After this point, we're fully operational.
        """
        self._active = True
        logger.warning("[%s] ACTIVATED — taking over from %s (reason: %s)",
                       self.backup_id, self.primary_id, reason)

        # Notify all agents in this subdomain to re-route to this backup
        for agent_id in self.agent_ids:
            await self._bus.send_to(
                receiver=agent_id,
                sender=self.backup_id,
                msg_type=MessageType.REGISTER,
                payload={
                    "failover":     True,
                    "redirect_to":  self.backup_id,
                    "old_primary":  self.primary_id,
                    "reason":       reason,
                }
            )

        # Start the aggregation loop now that we're active
        asyncio.create_task(self._aggregation_loop())

    def deactivate(self) -> None:
        """Called if primary recovers — returns to standby."""
        self._active = False
        logger.info("[%s] returned to STANDBY", self.backup_id)

    # ── State sync (import/export) ────────────────────────────────────────────

    def export_state(self) -> dict:
        return {
            "agent_beliefs":   self._agent_beliefs,
            "agent_last_seen": self._agent_last_seen,
        }

    def restore_state(self, state: dict) -> None:
        self._agent_beliefs   = state.get("agent_beliefs", {})
        self._agent_last_seen = state.get("agent_last_seen", {})
        logger.info("[%s] state restored — %d agents in sync",
                    self.backup_id, len(self._agent_beliefs))

    # ── Loops ─────────────────────────────────────────────────────────────────

    async def _message_loop(self) -> None:
        while self._running:
            msg = await self._bus.receive(self.backup_id, timeout=0.05)
            if not msg:
                continue

            # Always accept state sync from primary regardless of active state
            if (msg.msg_type == MessageType.BELIEF_UPDATE
                    and msg.sender == self.primary_id
                    and isinstance(msg.payload, dict)
                    and "agent_beliefs" in msg.payload):
                self.restore_state(msg.payload)
                continue

            # Only handle agent messages when active
            if self._active:
                await self._handle_message(msg)

    async def _aggregation_loop(self) -> None:
        """Runs only when active — mirrors SubdomainCoordinator logic."""
        while self._running and self._active:
            await asyncio.sleep(1.0)
            await self._aggregate_and_forward()

    async def _handle_message(self, msg: Message) -> None:
        sender = msg.sender
        self._agent_last_seen[sender] = time.time()

        if msg.msg_type == MessageType.REGISTER:
            self._agent_beliefs.setdefault(
                sender, BeliefVector(origin_id=sender)
            )

        elif msg.msg_type == MessageType.BELIEF_UPDATE:
            if isinstance(msg.payload, BeliefVector):
                self._agent_beliefs[sender] = msg.payload

        elif msg.msg_type == MessageType.ALERT:
            alert: AlertRecord = msg.payload
            self._alerts.append(alert)
            await self._bus.send_to(
                receiver=self.global_engine_id,
                sender=self.backup_id,
                msg_type=MessageType.ALERT,
                payload=alert,
            )

        elif msg.msg_type == MessageType.QUERY:
            await self._bus.send_to(
                receiver=sender,
                sender=self.backup_id,
                msg_type=MessageType.BELIEF_UPDATE,
                payload=self._aggregated_belief,
            )

    async def _aggregate_and_forward(self) -> None:
        active = self._get_active_agents()
        if not active:
            return
        vectors = [self._agent_beliefs[a] for a in active
                   if self._agent_beliefs.get(a)]
        if not vectors:
            return
        agg = BayesianInferenceEngine.aggregate_beliefs(vectors)
        self._aggregated_belief = BeliefVector(
            origin_id=self.backup_id, beliefs=agg
        )
        await self._bus.send_to(
            receiver=self.global_engine_id,
            sender=self.backup_id,
            msg_type=MessageType.BELIEF_UPDATE,
            payload=self._aggregated_belief,
        )

    def _get_active_agents(self) -> List[str]:
        now = time.time()
        return [aid for aid, ts in self._agent_last_seen.items()
                if now - ts < HEARTBEAT_TIMEOUT]

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def status(self) -> str:
        return "ACTIVE" if self._active else "STANDBY"
