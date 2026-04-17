"""
Asynchronous Message Bus — The "nervous system" of the security system.

Think of this like the postal service or a message routing system in a corporation.

Different parts of the security system (agents, coordinators, global engine, dashboard, etc)
need to send messages to each other. Instead of each component knowing how to connect directly
to every other component, they all use this central message bus.

How it works:
1. Each component registers a "mailbox" (queue) with the bus
2. When component A wants to send a message, it gives it to the bus
3. The bus routes the message to the appropriate mailbox(es)
4. Component B picks up the message from its mailbox

This is also called a "pub/sub" system (publish-subscribe).

NEW FEATURE: Taps
- Some nodes can register as "taps" - they receive a COPY of EVERY message
- Like wiretaps in old spy movies
- Used by the DashboardTap to monitor the entire system
"""

from __future__ import annotations
import asyncio
import logging
from typing import Dict, Optional, Set

from dids.core.models import Message, MessageType

logger = logging.getLogger(__name__)


class MessageBus:
    """
    Central message routing system (like a telephone exchange).
    
    This manages:
    - Registration of nodes (mailboxes)
    - Routing messages to the right recipient(s)
    - Collecting statistics (how many messages sent, dropped, etc)
    - Tapping (like eavesdropping on all messages)
    """

    def __init__(self, maxsize: int = 256) -> None:
        self._inboxes: Dict[str, asyncio.Queue] = {}  # All the mailboxes
        self._taps:    Set[str]                 = set()  # Nodes listening to everything
        self._maxsize = maxsize  # Max messages each queue can hold
        self._stats: Dict[str, int] = {"sent": 0, "dropped": 0, "broadcast": 0}

    # ------------------------------------------------------------------
    # Registration - Setting up mailboxes
    # ------------------------------------------------------------------

    def register(self, node_id: str) -> asyncio.Queue:
        """
        Register a new node (component) on the bus.
        
        This creates a mailbox for this node so it can receive messages.
        Each node gets a unique ID like "agent_a1" or "coord_g0".
        
        Returns the mailbox (queue) which the node can use to receive messages.
        """
        if node_id not in self._inboxes:
            self._inboxes[node_id] = asyncio.Queue(maxsize=self._maxsize)
            logger.debug("MessageBus: registered node '%s'", node_id)
        return self._inboxes[node_id]

    def deregister(self, node_id: str) -> None:
        """
        Unregister a node - it's shutting down or leaving the system.
        
        This removes its mailbox so it won't receive new messages.
        """
        self._inboxes.pop(node_id, None)
        self._taps.discard(node_id)
        logger.debug("MessageBus: deregistered node '%s'", node_id)

    def add_tap(self, node_id: str) -> None:
        """
        Make a node a "tap" - it receives a copy of EVERY message.
        
        This is used by the dashboard to see everything happening in the system,
        like a security camera monitoring all communications.
        
        The node must already be registered first.
        """
        if node_id not in self._inboxes:
            self.register(node_id)
        self._taps.add(node_id)
        logger.debug("MessageBus: '%s' added as tap", node_id)

    # ------------------------------------------------------------------
    # Sending messages
    # ------------------------------------------------------------------

    async def send(self, msg: Message) -> bool:
        """
        Route a message through the bus to its destination(s).
        
        If the message has a receiver name → deliver to that one node
        If the message has no receiver → broadcast to ALL other nodes
        
        Returns True if at least one mailbox got the message.
        """
        # Determine who should get this message
        targets = (
            list(self._inboxes.keys()) if not msg.receiver  # No receiver = broadcast to all
            else [msg.receiver]  # Specific receiver = just that node
        )
        if not msg.receiver:
            self._stats["broadcast"] += 1

        delivered = False
        for target in targets:
            if target == msg.sender:  # Don't send messages back to yourself
                continue
            inbox = self._inboxes.get(target)
            if inbox is None:
                logger.warning("MessageBus: unknown target '%s'", target)
                continue
            try:
                inbox.put_nowait(msg)  # Non-blocking: add immediately or fail
                delivered = True
                self._stats["sent"] += 1
            except asyncio.QueueFull:
                # The mailbox is full - message dropped (too many unread messages)
                self._stats["dropped"] += 1
                logger.warning("MessageBus: inbox full for '%s', message dropped", target)

        # ── Deliver copies to all tap nodes ─────────────────────────────────
        # Taps get a copy of everything regardless of receiver
        for tap_id in self._taps:
            if tap_id in targets or tap_id == msg.sender:
                continue  # Already delivered or it's ourselves
            tap_inbox = self._inboxes.get(tap_id)
            if tap_inbox:
                try:
                    tap_inbox.put_nowait(msg)
                except asyncio.QueueFull:
                    pass  # Taps are best-effort, we don't worry if they're overloaded

        return delivered

    async def send_to(self, receiver: str, sender: str,
                      msg_type: MessageType, payload=None) -> bool:
        """
        Convenience function to send a message to a specific receiver.
        
        This wraps up all the message details and uses send() to route it.
        """
        msg = Message(msg_type=msg_type, sender=sender,
                      receiver=receiver, payload=payload)
        return await self.send(msg)

    # ------------------------------------------------------------------
    # Receiving messages (non-blocking helper)
    # ------------------------------------------------------------------

    async def receive(self, node_id: str, timeout: float = 0.1) -> Optional[Message]:
        """
        Wait for a message to arrive in a node's mailbox.
        
        This is how nodes check for incoming messages.
        - If a message arrives before timeout: return the message
        - If timeout expires with no message: return None
        
        Example: Wait up to 0.1 seconds for a message
        """
        inbox = self._inboxes.get(node_id)
        if inbox is None:
            return None
        try:
            return await asyncio.wait_for(inbox.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    # ------------------------------------------------------------------
    # Health / introspection - Monitoring the bus health
    # ------------------------------------------------------------------

    def get_queue_depth(self, node_id: str) -> float:
        """
        Return how full a node's mailbox is (0.0 to 1.0).
        
        0.0 = empty (nothing queued)
        0.5 = half full
        1.0 = completely full
        
        This is used to detect if a node is overloaded (can't keep up with messages).
        """
        inbox = self._inboxes.get(node_id)
        if inbox is None or inbox.maxsize == 0:
            return 0.0
        return inbox.qsize() / inbox.maxsize

    @property
    def nodes(self):
        """Return a list of all registered node IDs."""
        return list(self._inboxes.keys())

    @property
    def stats(self):
        """Return statistics about bus usage (messages sent, dropped, etc)."""
        return dict(self._stats)
