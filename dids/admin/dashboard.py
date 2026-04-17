"""
System Administrator Dashboard — The "alert display screen" for the security system.

Think of this like a security guard's desk with a monitor. When security agents detect
something suspicious, they send alerts here. The dashboard displays them and keeps a record.

This is a PASSIVE component - it doesn't make decisions, it just watches and displays alerts.
A human administrator would look at this dashboard to understand what threats are happening.
"""

from __future__ import annotations
import asyncio
import logging
import time
from typing import List, Optional

from dids.core.models import AlertRecord, Message, MessageType, ThreatLevel
from dids.communication.bus import MessageBus

logger = logging.getLogger(__name__)


class AdminDashboard:
    """
    Passive alert sink and reporting node.
    
    What does "passive" mean?
    - It LISTENS for alerts from the security system
    - It STORES them in a list
    - It DISPLAYS them to the user
    - It does NOT make any decisions or take any actions

    Parameters
    ----------
    dashboard_id : A unique name for this dashboard (like "admin_dashboard")
    bus          : The message bus (communication system) used to receive alerts
    """

    def __init__(self, dashboard_id: str, bus: MessageBus) -> None:
        self.dashboard_id = dashboard_id
        self._bus         = bus
        self._alerts:     List[AlertRecord] = []  # List: keep track of all alerts received
        self._running     = False
        self._inbox       = bus.register(dashboard_id)  # Register to receive messages

    # ------------------------------------------------------------------
    # Lifecycle - Starting and stopping the dashboard
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start listening for incoming alerts."""
        self._running = True
        logger.info("[%s] started", self.dashboard_id)
        asyncio.create_task(self._message_loop())  # Start the listening loop in background

    async def stop(self) -> None:
        """Stop listening for alerts."""
        self._running = False
        self._bus.deregister(self.dashboard_id)

    # ------------------------------------------------------------------
    # Main listening loop - continuously checks for new alerts
    # ------------------------------------------------------------------

    async def _message_loop(self) -> None:
        """
        Continuously check for new alert messages from the bus.
        
        This is like checking a mailbox:
        1. Wait 0.05 seconds for a new alert message
        2. If we get one, record it
        3. Repeat forever
        """
        while self._running:
            msg = await self._bus.receive(self.dashboard_id, timeout=0.05)
            if msg and msg.msg_type == MessageType.ALERT:
                self._record_alert(msg.payload)

    def _record_alert(self, alert: AlertRecord) -> None:
        """
        Store a new alert in our list and print it to the screen.
        
        Think of this like writing down a suspicious event in a notebook.
        """
        self._alerts.append(alert)
        print(f"  🚨  {alert}")  # Print with a warning emoji so it stands out

    # ------------------------------------------------------------------
    # Reporting - Methods to summarize and display all alerts
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        """
        Print a nicely formatted summary of ALL alerts received so far.
        
        This shows:
        - Total number of alerts
        - Alerts grouped by severity (Critical, High, Medium, Low)
        - Details of each alert (timestamp, type, confidence, IP addresses)
        
        Similar to a security report you might give to management.
        """
        if not self._alerts:
            print("\n[Dashboard] No alerts received.")
            return

        print(f"\n{'='*70}")
        print(f"  DIDS ALERT SUMMARY  —  {len(self._alerts)} alert(s)")
        print(f"{'='*70}")

        # Group alerts by severity (threat level)
        by_level = {lvl: [] for lvl in ThreatLevel}
        for a in self._alerts:
            by_level[a.threat_level].append(a)

        # Print each severity level, starting with most severe
        for level in reversed(ThreatLevel):
            alerts = by_level[level]
            if alerts:
                print(f"\n  [{level.name}] ({len(alerts)} alerts)")
                for a in alerts:
                    ts = time.strftime("%H:%M:%S", time.localtime(a.timestamp))
                    print(f"    • {ts} | {a.attack_type.value:<22} "
                          f"p={a.probability:.2f} | src={a.source_node}")

        print(f"\n{'='*70}\n")

    @property
    def alert_count(self) -> int:
        """How many alerts have we received total?"""
        return len(self._alerts)

    @property
    def alerts(self) -> List[AlertRecord]:
        """Return a copy of the list of all alerts."""
        return list(self._alerts)

    def alerts_above(self, threshold: ThreatLevel) -> List[AlertRecord]:
        """
        Return only alerts that are above a certain severity level.
        
        Example: Show me only CRITICAL alerts, ignore the LOW ones.
        """
        return [a for a in self._alerts if a.threat_level.value >= threshold.value]
