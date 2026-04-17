"""
Health Monitor — The "doctor" who checks if components are alive and healthy.

Its jobs:
1. Continuously monitor the "pulse" (heartbeat) of each coordinator
2. Check if coordinator mailboxes are getting overloaded
3. If a coordinator is dead or sick, activate its backup
4. If a coordinator recovers, switch back to it

WHY USE A TAP?
Instead of asking coordinators "Are you alive?", it listens to ALL messages.
- Coordinators are busy working, they might ignore a query
- But if they're functional, they'll send messages about their work
- This way we observe them naturally, without interruption

FAILOVER RULES:
- If primary hasn't sent message in 30 seconds OR queue is >80% full
- AND this happens 2+ times in a row
- Then declare it dead and activate the backup
- The backup tries to recover after 20 seconds if primary looks healthy again
"""

from __future__ import annotations
import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, TYPE_CHECKING

from dids.communication.bus import MessageBus
from dids.core.models import Message

if TYPE_CHECKING:
    from dids.coordination.backup_coordinator import BackupCoordinator
    from dids.web.tap import DashboardTap

logger = logging.getLogger(__name__)

HEARTBEAT_TIMEOUT  = 30.0   # No message in 30 seconds = probably dead
OVERLOAD_THRESHOLD = 0.80   # Queue >80% full = overloaded/sick
RECOVERY_THRESHOLD = 0.20   # Queue <20% full = recovered
CHECK_INTERVAL     = 3.0    # Check health every 3 seconds
FAILBACK_GRACE     = 20.0   # Wait 20 seconds after failover before switching back
CONSECUTIVE_FAILS  = 2      # Fail 2+ times before doing failover
TAP_ID = "hm_tap"           # This monitor's ID


@dataclass
class NodePair:
    """
    Represents a primary coordinator and its backup.
    
    Used to track the state of a failed-over pair.
    - primary_id: Name of the main coordinator
    - backup_id: Name of the backup
    - active: Which one is currently active ("primary" or "backup")
    - failed_at: When the primary failed (for recovery timer)
    """
    primary_id:  str
    backup_id:   str
    primary_obj: object
    backup_obj:  "BackupCoordinator"
    active:      str   = "primary"  # Which is currently in charge
    failed_at:   float = 0.0        # When did it fail
    recovered_at: float = 0.0       # When did it recover
    _fails: int = field(default=0, repr=False)  # How many failures in a row


class HealthMonitor:
    """
    Watches coordinators and manages automatic failover.
    
    This uses a "tap" on the message bus - it gets a copy of every message.
    By observing message traffic, it can tell:
    - Is the coordinator responsive? (sends messages)
    - Is it overloaded? (queue fullness)
    - Should we failover? (health check logic)
    
    Parameters
    ----------
    bus : The message bus to tap
    tap : Optional reference to the DashboardTap for status updates
    """
    def __init__(self, bus: MessageBus,
                 tap: Optional["DashboardTap"] = None) -> None:
        self._bus    = bus
        self._tap    = tap
        self._pairs: Dict[str, NodePair] = {}  # All primary/backup pairs we monitor
        self._hb:    Dict[str, float]    = {}  # Last seen time for each node
        self._running = False
        self._inbox  = bus.register(TAP_ID)
        bus.add_tap(TAP_ID)  # Register as a tap to see all messages

    def register_pair(self, pair: NodePair) -> None:
        self._pairs[pair.primary_id] = pair
        now = time.time()
        self._hb[pair.primary_id] = now
        self._hb[pair.backup_id]  = now
        logger.info("[HealthMonitor] Pair: %s ↔ %s", pair.primary_id, pair.backup_id)

    async def start(self) -> None:
        self._running = True
        asyncio.create_task(self._tap_loop())
        asyncio.create_task(self._watch_loop())
        logger.info("[HealthMonitor] started (timeout=%.0fs)", HEARTBEAT_TIMEOUT)

    async def stop(self) -> None:
        self._running = False
        self._bus.deregister(TAP_ID)

    async def _tap_loop(self) -> None:
        """Any bus message from a coordinator resets its liveness timer."""
        while self._running:
            msg: Optional[Message] = await self._bus.receive(TAP_ID, timeout=0.05)
            if msg and msg.sender:
                if msg.sender in self._pairs:
                    self._hb[msg.sender] = time.time()
                for p in self._pairs.values():
                    if msg.sender == p.backup_id:
                        self._hb[p.backup_id] = time.time()

    async def _watch_loop(self) -> None:
        while self._running:
            await asyncio.sleep(CHECK_INTERVAL)
            for pair in list(self._pairs.values()):
                await self._check(pair)

    async def _check(self, pair: NodePair) -> None:
        now    = time.time()
        active = pair.primary_id if pair.active == "primary" else pair.backup_id
        age    = now - self._hb.get(active, now)  # How long since last message
        depth  = self._bus.get_queue_depth(active)  # How full is the queue (0.0-1.0)
        bad    = age > HEARTBEAT_TIMEOUT or depth > OVERLOAD_THRESHOLD

        if pair.active == "primary":
            if bad:
                # Primary is not responsive or overloaded
                pair._fails += 1
                reason = f"heartbeat:{age:.1f}s" if age > HEARTBEAT_TIMEOUT else f"overload:{depth*100:.0f}%"
                logger.warning("[HealthMonitor] %s bad (%d/%d): %s", active, pair._fails, CONSECUTIVE_FAILS, reason)
                if pair._fails >= CONSECUTIVE_FAILS:
                    # Multiple failures - declare it dead and failover
                    await self._failover(pair, reason)
                    pair._fails = 0
            else:
                # Primary is healthy
                pair._fails = 0
        else:
            # We're currently using the backup - check if primary recovered
            pa = now - self._hb.get(pair.primary_id, 0)  # Primary's age
            pd = self._bus.get_queue_depth(pair.primary_id)  # Primary's queue
            if (pa < HEARTBEAT_TIMEOUT and pd < RECOVERY_THRESHOLD
                    and pair.failed_at > 0 and now - pair.failed_at > FAILBACK_GRACE):
                # Primary is healthy again and we've waited long enough
                await self._failback(pair)

    async def _failover(self, pair: NodePair, reason: str) -> None:
        """
        Switch from primary to backup.
        
        This is a major event - report it to logs and the dashboard.
        """
        logger.warning("[HealthMonitor] FAILOVER %s→%s (%s)", pair.primary_id, pair.backup_id, reason)
        pair.active = "backup"
        pair.failed_at = time.time()
        # Transfer state from primary to backup before activating it
        if hasattr(pair.primary_obj, "export_state"):
            pair.backup_obj.restore_state(pair.primary_obj.export_state())
        await pair.backup_obj.activate(reason=reason)
        if self._tap:
            self._tap.update_backup_status(pair.backup_id, pair.primary_id, True, reason)

    async def _failback(self, pair: NodePair) -> None:
        """
        Switch back from backup to primary (primary has recovered).
        """
        logger.info("[HealthMonitor] FAILBACK %s", pair.primary_id)
        pair.active = "primary"
        pair.recovered_at = time.time()
        pair.failed_at = 0.0
        pair._fails = 0
        pair.backup_obj.deactivate()  # Backup goes back to standby mode
        if self._tap:
            self._tap.update_backup_status(pair.backup_id, pair.primary_id, False, "recovered")

    def get_status(self) -> List[dict]:
        now = time.time()
        return [{"primary_id": p.primary_id, "backup_id": p.backup_id,
                 "active": p.active, "failed_at": p.failed_at,
                 "last_seen_s": round(now - self._hb.get(p.primary_id, 0), 1),
                 "q_primary": round(self._bus.get_queue_depth(p.primary_id), 3)}
                for p in self._pairs.values()]