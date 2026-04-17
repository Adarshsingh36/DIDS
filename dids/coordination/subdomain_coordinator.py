"""
Subdomain Coordinator — A "regional manager" who aggregates reports from multiple agents.

Think of an organizational structure:
- Each MonitoringAgent is like a front-line security guard (watches one building)
- Each SubdomainCoordinator is like a regional manager who collects reports from 3-4 guards
- The GlobalDetectionEngine is the CEO who gets reports from all regional managers

Each coordinator received belief vectors (opinions) from its agents and:
1. Combines them using probabilistic reasoning
2. Sends the combined report to the global engine
3. Handles alerts from agents
4. Respects agent heartbeats to know which agents are still alive
5. Removes "stale" agents that haven't checked in for 15 seconds

This creates a hierarchical security architecture - like a pyramid where local detection
filters and aggregates before sending to central command.
"""

from __future__ import annotations
import asyncio
import logging
import time
from typing import Dict, List, Optional, Set

from dids.core.models import (
    AlertRecord, BeliefVector,
    Message, MessageType, ThreatLevel,
)
from dids.communication.bus import MessageBus
from dids.inference.bayesian import BayesianInferenceEngine

logger = logging.getLogger(__name__)

HEARTBEAT_TIMEOUT = 15.0    # If an agent hasn't sent a heartbeat in 15 seconds, consider it dead
AGGREGATION_INTERVAL = 1.0  # Combine agent beliefs every 1 second


class SubdomainCoordinator:
    """
    Coordinates a group of MonitoringAgents within a logical subdomain.
    
    Responsibilities:
    - Receive belief updates and alerts from agents
    - Track which agents are alive (via heartbeats)
    - Combine beliefs from all alive agents
    - Forward combined beliefs to the GlobalDetectionEngine
    - Handle alerts and forward them up the chain

    Parameters
    ----------
    coordinator_id : unique node identifier (e.g. "coord_g0")
    global_engine_id : node_id of the GlobalDetectionEngine (where to send reports)
    bus            : shared MessageBus for communication
    """

    def __init__(self, coordinator_id: str,
                 global_engine_id: str, bus: MessageBus) -> None:
        self.coordinator_id   = coordinator_id       # This coordinator's name
        self.global_engine_id = global_engine_id     # Where to send aggregated reports
        self._bus             = bus
        self._engine          = BayesianInferenceEngine()  # The thinking tool

        self._agent_beliefs:    Dict[str, BeliefVector] = {}  # Latest belief from each agent
        self._agent_last_seen:  Dict[str, float]        = {}  # When we last heard from agent
        self._agents:           Set[str]                = set()  # All agents we coordinate
        self._aggregated_belief = BeliefVector(origin_id=coordinator_id)  # Our combined opinion
        self._alerts:           List[AlertRecord]       = []  # All alerts received
        self._running           = False

        self._inbox = bus.register(coordinator_id)

    # ------------------------------------------------------------------
    # Lifecycle - Starting and stopping the coordinator
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """
        Start the coordinator.
        
        This launches two background tasks:
        1. _message_loop: Listen for incoming messages from agents/global engine
        2. _aggregation_loop: Every second, combine beliefs and send to global engine
        """
        self._running = True
        logger.info("[%s] started", self.coordinator_id)
        asyncio.create_task(self._message_loop())
        asyncio.create_task(self._aggregation_loop())

    async def stop(self) -> None:
        """Stop the coordinator and cleanup."""
        self._running = False
        self._bus.deregister(self.coordinator_id)

    # ------------------------------------------------------------------
    # Loops - Main work happens here
    # ------------------------------------------------------------------

    async def _message_loop(self) -> None:
        """
        Main listening loop - process incoming messages one by one.
        
        This continuously:
        1. Wait for a message from an agent
        2. Process it (update beliefs, record alerts, etc)
        3. Repeat
        """
        while self._running:
            msg = await self._bus.receive(self.coordinator_id, timeout=0.05)
            if msg:
                await self._handle_message(msg)

    async def _aggregation_loop(self) -> None:
        """
        Periodically combine all agent beliefs and send to global engine.
        
        Every 1 second, this:
        1. Gets beliefs from all currently-alive agents
        2. Combines them using probabilistic math
        3. Sends the combined result to the global engine
        
        This is where multiple agents' opinions are merged into one viewpoint.
        """
        while self._running:
            await asyncio.sleep(AGGREGATION_INTERVAL)
            await self._aggregate_and_forward()

    # ------------------------------------------------------------------
    # Message handling - React to incoming messages
    # ------------------------------------------------------------------

    async def _handle_message(self, msg: Message) -> None:
        """
        Process an incoming message. Different handling for different message types.
        """
        sender = msg.sender
        self._agent_last_seen[sender] = time.time()  # Update "last contact" time

        if msg.msg_type == MessageType.REGISTER:
            # An agent is saying hello and registering with this coordinator
            logger.info("[%s] registered agent %s", self.coordinator_id, sender)
            self._agents.add(sender)
            # Initialize empty belief vector for this agent (we'll fill it later)
            self._agent_beliefs.setdefault(
                sender, BeliefVector(origin_id=sender)
            )

        elif msg.msg_type == MessageType.BELIEF_UPDATE:
            # An agent is sending its current belief/opinion about what's happening
            bv: BeliefVector = msg.payload
            self._agent_beliefs[sender] = bv
            logger.debug("[%s] received belief update from %s (max_p=%.2f)",
                         self.coordinator_id, sender, bv.max_probability())

        elif msg.msg_type == MessageType.ALERT:
            # An agent raised an alert - it's confident an attack is happening
            alert: AlertRecord = msg.payload
            self._alerts.append(alert)
            # Immediately escalate the alert to the global engine (don't wait)
            await self._bus.send_to(
                receiver=self.global_engine_id,
                sender=self.coordinator_id,
                msg_type=MessageType.ALERT,
                payload=alert,
            )

        elif msg.msg_type == MessageType.TRUST_VERIFY:
            # Forwarding cooperative alerts between agents
            if msg.payload and msg.payload.get("cooperative_alert"):
                logger.debug("[%s] forwarding cooperative alert from %s to peers",
                             self.coordinator_id, sender)
                # Tell all other agents to be extra vigilant
                for agent_id in self._agents:
                    if agent_id == sender:
                        continue
                    await self._bus.send_to(
                        receiver=agent_id,
                        sender=self.coordinator_id,
                        msg_type=MessageType.TRUST_VERIFY,
                        payload=msg.payload,
                    )

        elif msg.msg_type == MessageType.HEARTBEAT:
            # Agent is still alive (timestamp was already updated above)
            pass

        elif msg.msg_type == MessageType.QUERY:
            # Someone is asking "what do you think?" - send our aggregated belief
            await self._bus.send_to(
                receiver=sender,
                sender=self.coordinator_id,
                msg_type=MessageType.BELIEF_UPDATE,
                payload=self._aggregated_belief,
            )

    # ------------------------------------------------------------------
    # Aggregation - Combining beliefs from multiple agents
    # ------------------------------------------------------------------

    async def _aggregate_and_forward(self) -> None:
        """
        Combine beliefs from all alive agents and send the result upward.
        
        This is like a manager summarizing reports from multiple team members.
        """
        active = self._get_active_agents()
        if not active:
            return  # No active agents, nothing to aggregate

        # Get belief vectors from all active agents
        vectors = [self._agent_beliefs[a] for a in active if self._agent_beliefs.get(a)]
        if not vectors:
            return

        # Use Bayesian math to combine them
        agg = BayesianInferenceEngine.aggregate_beliefs(vectors)
        self._aggregated_belief = BeliefVector(
            origin_id=self.coordinator_id,
            beliefs=agg,
        )


        # Send the combined belief to the global engine  
        await self._bus.send_to(
            receiver=self.global_engine_id,
            sender=self.coordinator_id,
            msg_type=MessageType.BELIEF_UPDATE,
            payload=self._aggregated_belief,
        )

    def _get_active_agents(self) -> List[str]:
        """
        Return which agents are still alive and responsive.
        
        If an agent hasn't sent a heartbeat in 15 seconds, we assume it's dead.
        """
        now = time.time()
        return [
            aid for aid, ts in self._agent_last_seen.items()
            if now - ts < HEARTBEAT_TIMEOUT
        ]

    # ------------------------------------------------------------------
    # Properties - Allow external code to query our state
    # ------------------------------------------------------------------

    @property
    def aggregated_belief(self) -> BeliefVector:
        """Return our current combined opinion about threats."""
        return self._aggregated_belief

    @property
    def active_agents(self) -> List[str]:
        """Return list of agents currently alive."""
        return self._get_active_agents()

    @property
    def alerts(self) -> List[AlertRecord]:
        """Return all alerts we've received."""
        return list(self._alerts)
