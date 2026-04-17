"""
Monitoring Agent — A "security guard" stationed at one host/computer.

This agent's job is to:
1. Watch for suspicious events happening on its assigned computer (failed logins, port scans, etc)
2. Think about what type of attack these events might indicate (using probability calculations)
3. Report its findings to a coordinator (like reporting to headquarters)
4. Listen for instructions from the coordinator
5. Send heartbeats every 5 seconds so the coordinator knows it's still alive

Think of it like a security camera operator on a single floor - they see local events
and report them up the chain of command. They don't make final decisions, they just
observe and report what they see.

WINDOW_SIZE: We keep the last 50 events to analyze patterns (like "3 failed logins in 10 seconds")
ALERT_THRESHOLD: If we're 55% confident it's an attack, we send an alert
"""

from __future__ import annotations
import asyncio
import logging
import time
from typing import Deque, List
from collections import deque

from dids.core.models import (
    AlertRecord, BeliefVector, Message, MessageType, SecurityEvent,
)
from dids.communication.bus import MessageBus
from dids.inference.bayesian import BayesianInferenceEngine

logger = logging.getLogger(__name__)
ALERT_THRESHOLD = 0.55  # 55% confidence needed to raise an alert
WINDOW_SIZE     = 50    # Remember the last 50 events


class MonitoringAgent:
    """
    A single-host security monitor (like a security officer on one floor).
    
    This agent:
    - Watches for security events (failed logins, port scans, etc)
    - Maintains a belief/opinion about whether an attack is happening
    - Reports suspicious activity to its coordinator
    - Listens for feedback and instructions
    
    Each agent is assigned to ONE host/computer and the agent_id and host_id are used
    to identify which computer it's watching.
    """
    def __init__(self, agent_id: str, host_id: str,
                 coordinator_id: str, bus: MessageBus) -> None:
        self.agent_id       = agent_id          # This agent's ID (like "agent_a1")
        self.host_id        = host_id           # The computer it watches (like "h_a1")
        self.coordinator_id = coordinator_id    # Where to send reports (like "coord_g0")
        self._bus           = bus
        self._engine        = BayesianInferenceEngine()  # The "thinking" component
        self._window: Deque[SecurityEvent] = deque(maxlen=WINDOW_SIZE)  # Last 50 events
        self._belief        = BeliefVector(origin_id=agent_id)  # Current opinion on threats
        self._alerts: List[AlertRecord] = []    # Alerts we've raised
        self._running       = False
        self._last_hb       = 0.0                # When we last sent a heartbeat
        self._inbox         = bus.register(agent_id)

    async def start(self) -> None:
        """
        Start the monitoring agent.
        
        This:
        1. Registers this agent with its coordinator (so HQ knows it exists)
        2. Starts the main thinking loop (which continuously processes events)
        """
        self._running = True
        await self._register()
        logger.info("[%s] started", self.agent_id)
        asyncio.create_task(self._run_loop())

    async def stop(self) -> None:
        """Stop the agent and unregister from the bus."""
        self._running = False
        self._bus.deregister(self.agent_id)

    # ── Receiving live events from the network sniffer ────────────────────────────

    async def on_network_event(self, event_type: str,
                                source_ip: str, payload: dict) -> None:
        """
        A callback function called whenever the network monitor detects something.
        
        Example: The network monitor detected a port scan from 192.168.1.100
        It calls this function with:
          event_type = "port_scan_detected"
          source_ip = "192.168.1.100"
          payload = {details about the scan}
        
        This is the main way events get into the agent.
        """
        event = SecurityEvent.create(
            agent_id=self.agent_id,
            host_id=self.host_id,
            event_type=event_type,
            source_ip=source_ip,
            payload=payload,
        )
        logger.info("[%s] LIVE %s from %s", self.agent_id, event_type, source_ip)
        await self.ingest_event(event)

    async def ingest_event(self, event: SecurityEvent) -> None:
        """
        Process a new security event.
        
        This:
        1. Adds the event to our sliding window (last 50 events)
        2. Re-analyzes all events in the window using probability calculations
        3. Updates our belief about whether an attack is happening
        """
        self._window.append(event)
        await self._process()

    async def _run_loop(self) -> None:
        """
        Main loop - runs continuously waiting for:
        1. Incoming messages from the coordinator (queries, instructions)
        2. Time to send a heartbeat (every 5 seconds)
        """
        while self._running:
            msg = await self._bus.receive(self.agent_id, timeout=0.05)
            if msg:
                await self._handle(msg)
            if time.time() - self._last_hb > 5.0:
                await self._heartbeat()

    async def _handle(self, msg: Message) -> None:
        """
        React to messages from the coordinator.
        
        Message types we understand:
        - QUERY: Coordinator asks "what do you think is happening?"  → Send our belief
        - REGISTER: Coordinator tells us to redirect to a backup → Update coordinator_id
        """
        if msg.msg_type == MessageType.QUERY:
            # Coordinator is asking for our current belief/opinion
            await self._bus.send_to(msg.sender, self.agent_id,
                                    MessageType.BELIEF_UPDATE, self._belief)
        elif msg.msg_type == MessageType.REGISTER:
            # Check if this is a failover message (primary coordinator went down, use backup)
            p = msg.payload or {}
            if p.get("failover") and p.get("redirect_to"):
                self.coordinator_id = p["redirect_to"]  # Change where we report to
                logger.warning("[%s] Failover → %s", self.agent_id, self.coordinator_id)

    async def _process(self) -> None:
        """
        Re-analyze recent events and update our belief about what's happening.
        
        This is the "thinking" step:
        1. Take all events from the last 50 recorded
        2. Use probabilistic reasoning to calculate: what's the likelihood of each attack type?
        3. Update our internal belief vector
        4. Send the updated belief to our coordinator
        5. If confidence is high enough, raise an alert
        """
        if not self._window:
            return
        # Use Bayesian inference to compute a new belief based on recent events
        bv = self._engine.update_belief_vector(self._belief, list(self._window))
        self._belief = bv
        # Report our new belief to the coordinator
        await self._bus.send_to(self.coordinator_id, self.agent_id,
                                MessageType.BELIEF_UPDATE, bv)
        # If confidence passes threshold, raise an alert
        if bv.max_probability() >= ALERT_THRESHOLD:
            await self._alert(bv)

    async def _alert(self, bv: BeliefVector) -> None:
        """
        We're confident enough that an attack is happening - raise an alert!
        
        This creates an AlertRecord with:
        - The attack type we think it is (BRUTE_FORCE, PORT_SCAN, etc)
        - Our confidence level (0.0 to 1.0)
        - The severity level (CRITICAL, HIGH, MEDIUM, etc)
        - Evidence (the last 10 events that led to this conclusion)
        - The IPs involved in the suspicious activity
        
        Then we send this alert up to the coordinator.
        """
        rec = AlertRecord(
            source_node=self.agent_id,
            attack_type=bv.dominant_threat(),
            probability=bv.max_probability(),
            threat_level=bv.threat_level(),
            evidence=[e.event_id for e in list(self._window)[-10:]],
            involved_ips=list({e.source_ip for e in self._window if e.source_ip}),
        )
        self._alerts.append(rec)
        logger.warning("[%s] %s", self.agent_id, rec)
        # Send the alert to the coordinator
        await self._bus.send_to(self.coordinator_id, self.agent_id,
                                MessageType.ALERT, rec)

    async def _register(self) -> None:
        """
        Say hello to the coordinator - "I exist and I'm watching host_id".
        
        This is like introducing yourself to your supervisor so they know you're now
        part of the team and should expect reports from you.
        """
        await self._bus.send_to(self.coordinator_id, self.agent_id,
                                MessageType.REGISTER, {"host_id": self.host_id})

    async def _heartbeat(self) -> None:
        """
        Send a "I'm alive" message to the coordinator every 5 seconds.
        
        This is like checking in so the coordinator knows:
        1. This agent is still running
        2. This agent is responsive (not frozen or crashed)
        
        If we don't send heartbeats for too long, the coordinator will think we're dead
        and may activate a backup agent to cover our host.
        """
        self._last_hb = time.time()
        await self._bus.send_to(self.coordinator_id, self.agent_id,
                                MessageType.HEARTBEAT, {"ts": self._last_hb})

    @property
    def current_belief(self) -> BeliefVector:
        """Return our current opinion about what's happening."""
        return self._belief

    @property
    def alerts(self) -> List[AlertRecord]:
        """Return a list of all alerts we've raised."""
        return list(self._alerts)