"""
DASHBOARD TAP — The Real-Time Web Bridge

ANALOGY
───────
Imagine the internal message bus as a postal system where all components mail each other
alerts and status updates. The tap is like a postal worker who:

1. LISTENS to every letter passing through (receives copy of every message)
2. TRANSLATES letters to web-friendly format (JSON)
3. BROADCASTS to all connected web browsers (via WebSocket queues)
4. MAINTAINS a snapshot of latest state (so new browsers see current status instantly)

WHY NEEDED?
──────────
- Internal system uses Python objects and asyncio queues (efficient but not web-friendly)
- Web browsers need JSON (text-based data format)
- WebSocket clients need push notifications (server sends data without browser requesting)
- New browser connections need instant current state (not just future events)

ARCHITECTURE
────────────
MessageBus
   │
   ├─ Internal components (Agents, Coordinators, Trust Manager, etc.)
   │  └─ All send/receive messages
   │
   ├─ Tap node (this module)
   │  ├─ Registers as "dashboard_tap" on bus
   │  ├─ Receives copy of EVERY message
   │  ├─ Serializes to JSON
   │  ├─ Maintains state snapshot
   │  └─ Routes to connected clients
   │
   └─ Connected WebSocket clients (web browsers)
      └─ Each has asyncio.Queue for receiving updates


HOW DATA FLOWS
──────────────
Step 1: Component sends message to bus
        Agent → "Hey, I think there's a brute force attack (60% confidence)"
        
Step 2: Bus has tap registered, so:
        Bus → routes to destination (Coordinator, GlobalEngine)
        Bus → ALSO sends copy to tap

Step 3: Tap._listen() receives copy:
        Tap → "Oh, a belief update from agent_a1"
        Tap → Serialize: {"type": "belief_update", "sender": "agent_a1", ...}
        Tap → Broadcast to all WebSocket client queues

Step 4: WebSocket handlers receive from client queues:
        WebSocket handler → receives JSON string from its queue
        WebSocket handler → sends to connected browser

Step 5: Browser JavaScript receives:
        Browser → parses JSON
        Browser → updates threat level chart, agent status tiles, etc.
        Browser → user sees real-time update instantly

NEW BROWSER CONNECTION FLOW
──────────────────────────
1. Browser opens http://localhost:8000
2. JavaScript connects: new WebSocket("ws://localhost:8000/ws")
3. FastAPI WebSocket endpoint calls tap.add_client()
4. Tap._send_snapshot() runs, sends full current state as one JSON
5. Browser receives snapshot: all agents, all recent alerts, all coordinator beliefs
6. Browser renders initial dashboard display
7. From now on, browser receives live update messages
8. Result: New browser instantly sees full picture (not just "no data yet")

MESSAGE TYPES SERIALIZED
─────────────────────────
- BELIEF_UPDATE: Agent/coordinator belief vector (with probabilities for each attack type)
- ALERT: Confirmed security alert (from global engine or trust manager)
- HEARTBEAT: "I'm alive" pulse (all components send every 5 seconds)
- TRUST_VERIFY: Trust voting initiated (suspicious node detected)
- TRUST_VOTE: Trust vote cast (component votes on suspect)
- REGISTER: Component registration (with optional failover notification)

STATE MAINTAINED
────────────────
_agent_beliefs: {}         - Latest belief from each agent
_agent_trust: {}           - Latest trust score for each agent
_coord_beliefs: {}         - Latest belief from each coordinator
_global_belief: None       - Latest system-wide belief
_recent_alerts: []         - Last 100 alerts (newest first)
_backup_status: {}         - Status of all backup coordinators
_heartbeats: {}            - Timestamp of last heartbeat from each component
"""

from __future__ import annotations
import asyncio
import json
import logging
import time
from dataclasses import asdict
from enum import Enum
from typing import Any, Dict, Optional, Set

from dids.core.models import (
    AlertRecord, BeliefVector, Message, MessageType, AttackType, ThreatLevel
)
from dids.communication.bus import MessageBus

logger = logging.getLogger(__name__)


# ── JSON serialiser ───────────────────────────────────────────────────────────

def _safe_json(obj: Any) -> Any:
    """Recursively convert non-JSON-native types to serialisable forms."""
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {k: _safe_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_safe_json(i) for i in obj]
    if hasattr(obj, '__dict__'):
        return _safe_json(obj.__dict__)
    return obj


def _serialize_alert(alert: AlertRecord) -> dict:
    return {
        "alert_id":    alert.alert_id[:8],
        "timestamp":   alert.timestamp,
        "source_node": alert.source_node,
        "attack":      alert.attack_type.value,
        "probability": round(alert.probability, 4),
        "level":       alert.threat_level.name,
        "involved_ips": alert.involved_ips,
        "evidence":    alert.evidence[:5],
    }


def _serialize_belief(bv: BeliefVector) -> dict:
    return {
        "origin_id":  bv.origin_id,
        "beliefs":    {k: round(v, 4) for k, v in bv.beliefs.items()},
        "max_p":      round(bv.max_probability(), 4),
        "dominant":   bv.dominant_threat().value,
        "threat_level": bv.threat_level().name,
    }


# ── Main class ────────────────────────────────────────────────────────────────

class DashboardTap:
    """
    The Web Browser Bridge — Translates internal system events to web format.
    
    WHAT IT DOES
    ────────────
    1. Eavesdrops on the internal message bus (tap mode, doesn't interfere)
    2. For each message:
       - Determines message type (alert, belief, heartbeat, etc.)
       - Extracts relevant data
       - Converts Python objects to JSON-serializable dicts
       - Broadcasts to all connected WebSocket clients
       - Updates internal state snapshot
    
    3. When new browser connects:
       - Sends complete current state snapshot (instant populated dashboard)
       - Then sends all live updates going forward
    
    KEY PROPERTIES
    ──────────────
    bus : MessageBus
        The shared message routing system. Tap registers itself as "dashboard_tap"
        and asks bus to send copy of every message.
    
    _clients : Set[asyncio.Queue]
        One queue per connected WebSocket client. When message arrives, tap puts
        it in all client queues. WebSocket handlers remove from their queue and
        send to browser. If queue full, client gets dropped (too slow).
    
    EXAMPLE STATE SNAPSHOT FOR NEW CLIENT
    ─────────────────────────────────────
    {
      "type": "snapshot",
      "agent_beliefs": {
        "agent_a1": {
          "origin_id": "agent_a1",
          "beliefs": {"brute_force": 0.8234, "ddos": 0.0234, ...},
          "dominant": "brute_force",
          "max_p": 0.8234,
          "threat_level": "HIGH"
        },
        ...
      },
      "agent_trust": {
        "agent_a1": {"trust": 0.95, "status": "TRUSTED"},
        ...
      },
      "coord_beliefs": {...},
      "global_belief": {...},
      "recent_alerts": [{alert1}, {alert2}, ...],
      "backup_status": {...},
      "heartbeats": {"agent_a1": 1234567890.5, ...}
    }
    """

    TAP_ID = "dashboard_tap"

    def __init__(self, bus: MessageBus) -> None:
        self._bus      = bus
        self._clients: Set[asyncio.Queue] = set()
        self._running  = False

        # Latest known state per node (for new-connection snapshots)
        self._agent_beliefs:   Dict[str, dict] = {}
        self._agent_trust:     Dict[str, dict] = {}
        self._coord_beliefs:   Dict[str, dict] = {}
        self._global_belief:   Optional[dict]  = None
        self._recent_alerts:   list            = []   # last 100
        self._backup_status:   Dict[str, dict] = {}
        self._heartbeats:      Dict[str, float]= {}

        # Register on bus as a tap
        self._inbox = bus.register(self.TAP_ID)
        bus.add_tap(self.TAP_ID)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """
        Start listening to the message bus.
        
        Launches background task (_listen) that:
        1. Continuously receives messages from tap queue
        2. Processes each message (serialize, update state, broadcast)
        3. Runs forever until stop() called
        
        Safe to call multiple times (idempotent).
        """
        self._running = True
        asyncio.create_task(self._listen())
        logger.info("[DashboardTap] started")

    async def stop(self) -> None:
        self._running = False
        self._bus.deregister(self.TAP_ID)

    # ── Client management ─────────────────────────────────────────────────────

    def add_client(self) -> asyncio.Queue:
        """
        Register a new WebSocket client (new browser window).
        
        FLOW
        ────
        1. Create asyncio.Queue (async message queue, max 512 messages)
        2. Add to _clients set (so broadcasts will include this queue)
        3. Immediately send full state snapshot (current agents, alerts, beliefs, etc.)
        4. Return queue to WebSocket handler
        5. WebSocket handler will read from queue and send to browser
        
        Why snapshot?
        - If browser connected AFTER system was running, it needs to see
          current state, not just future events
        - Results in populated dashboard instantly (not empty, gradually filling)
        - User sees full picture on connect
        
        Returns
        ───────
        asyncio.Queue: Message queue for this client
                       WebSocket handler reads from this queue
                       Tap puts messages into this queue
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=512)
        self._clients.add(q)
        # Send full state snapshot to the new client
        asyncio.create_task(self._send_snapshot(q))
        return q

    def remove_client(self, q: asyncio.Queue) -> None:
        self._clients.discard(q)

    # ── Internal listener ─────────────────────────────────────────────────────

    async def _listen(self) -> None:
        """
        Continuous message receiver from the bus tap.
        
        LOOP (runs forever)
        ───────────────────
        1. Wait for message from tap queue (50ms timeout)
        2. If message arrived: call _process(msg)
        3. If timeout (no message): loop back (no blocking)
        4. Repeat until stop() called
        
        This is the heart of the tap. It maintains the streaming connection
        to the internal bus and forwards all traffic to web clients.
        
        The non-blocking design (50ms timeout) allows graceful shutdown
        without hanging if no messages are flowing.
        """
        while self._running:
            msg: Optional[Message] = await self._bus.receive(
                self.TAP_ID, timeout=0.05
            )
            if msg:
                await self._process(msg)

    async def _process(self, msg: Message) -> None:
        """
        Process one message: classify → serialize → broadcast.
        
        FLOW FOR EACH MESSAGE
        ────────────────────
        1. Check message type (BELIEF_UPDATE, ALERT, HEARTBEAT, etc.)
        2. Extract payload based on type
        3. Serialize to JSON-friendly dict
        4. Update internal state tracking
        5. Create broadcast JSON object
        6. Send to all WebSocket clients
        
        BELIEF_UPDATE
        - Source: Agent, Coordinator, or GlobalEngine
        - Contains: Belief vector (probabilities for each attack type)
        - Stored: In _agent_beliefs, _coord_beliefs, or _global_belief
        - Broadcast: {"type": "belief_update", "sender": "...", "beliefs": {...}, ...}
        
        ALERT
        - Source: GlobalEngine or TrustManager
        - Contains: Alert record (confirmed attack)
        - Stored: In _recent_alerts (keep last 100)
        - Broadcast: {"type": "alert", "source_node": "...", "attack": "...", ...}
        
        HEARTBEAT
        - Source: Any component (agents, coordinators, etc.)
        - Meaning: "I'm still alive"
        - Stored: In _heartbeats (timestamp)
        - Broadcast: {"type": "heartbeat", "sender": "...", "ts": ...}
        
        TRUST_VERIFY & TRUST_VOTE
        - Related to Byzantine trust voting
        - Stored: Recently used for trust tracking
        - Broadcast: {"type": "trust_event" or "trust_vote", ...}
        
        REGISTER (with failover)
        - Source: Backup coordinator activation
        - Meaning: "Primary failed, I'm taking over"
        - Broadcast: {"type": "failover", "old_node": "...", "new_node": "..."}
        """
        payload = None

        if msg.msg_type == MessageType.BELIEF_UPDATE:
            bv: BeliefVector = msg.payload
            if not isinstance(bv, BeliefVector):
                return
            serialised = _serialize_belief(bv)
            # Track where the belief came from
            if msg.sender.startswith("agent_"):
                self._agent_beliefs[msg.sender] = serialised
                payload = {"type": "belief_update",
                           "node_type": "agent",
                           "sender": msg.sender,
                           **serialised}
            elif msg.sender.startswith("coord_"):
                self._coord_beliefs[msg.sender] = serialised
                payload = {"type": "belief_update",
                           "node_type": "coordinator",
                           "sender": msg.sender,
                           **serialised}
            elif msg.sender == "global_engine":
                self._global_belief = serialised
                payload = {"type": "belief_update",
                           "node_type": "global",
                           "sender": msg.sender,
                           **serialised}

        elif msg.msg_type == MessageType.ALERT:
            alert: AlertRecord = msg.payload
            if not isinstance(alert, AlertRecord):
                return
            serialised = _serialize_alert(alert)
            self._recent_alerts.insert(0, serialised)
            self._recent_alerts = self._recent_alerts[:100]
            payload = {"type": "alert", **serialised}

        elif msg.msg_type == MessageType.HEARTBEAT:
            self._heartbeats[msg.sender] = time.time()
            payload = {"type": "heartbeat",
                       "sender": msg.sender,
                       "ts": time.time()}

        elif msg.msg_type == MessageType.TRUST_VERIFY:
            p = msg.payload or {}
            payload = {"type": "trust_event",
                       "sender": msg.sender,
                       "suspect": p.get("source_node"),
                       "level": p.get("threat_level"),
                       "ts": time.time()}

        elif msg.msg_type == MessageType.TRUST_VOTE:
            p = msg.payload or {}
            payload = {"type": "trust_vote",
                       "sender": msg.sender,
                       "suspect": p.get("suspect"),
                       "phase": p.get("phase"),
                       "ts": time.time()}

        elif msg.msg_type == MessageType.REGISTER:
            p = msg.payload or {}
            # Detect failover notifications
            if p.get("failover"):
                payload = {"type": "failover",
                           "old_node": p.get("old_node"),
                           "new_node": p.get("new_node"),
                           "reason":   p.get("reason"),
                           "ts": time.time()}

        if payload:
            await self._broadcast(json.dumps(payload, default=str))

    # ── Broadcast helpers ─────────────────────────────────────────────────────

    async def _broadcast(self, text: str) -> None:
        """
        Send message to all connected WebSocket clients (fast path).
        
        HOW IT WORKS
        ────────────
        1. Iterate over all client queues
        2. Try to put message in queue (non-blocking)
        3. If queue full: client is too slow, drop it (add to dead set)
        4. Remove dead clients from tracking
        
        Why drop slow clients?
        - Queue max size is 512 messages
        - If client not reading, queue fills up
        - If we keep adding, we'll block the whole tap
        - Better to disconnect slow client than freeze the system
        
        This is a "best-effort" broadcast:
        - Fast clients get all messages
        - Very slow clients may miss some messages
        - Slower than necessary? Probably not acceptable in production
        - But works well for demos (clients on same machine)
        
        Parameters
        ──────────
        text : str
            JSON-serialized message to broadcast (string)
        """
        dead = set()
        for q in self._clients:
            try:
                q.put_nowait(text)
            except asyncio.QueueFull:
                dead.add(q)
        self._clients -= dead

    async def _send_snapshot(self, q: asyncio.Queue) -> None:
        """
        Send full current state to a newly connected client.
        
        WHY SNAPSHOT?
        ─────────────
        Imagine a browser connects after the system has been running for 30 minutes:
        - Without snapshot: Dashboard would be empty (no historical data)
        - With snapshot: Dashboard instantly shows all agents, recent alerts, beliefs
        
        This snapshot is the "initial state" received on WebSocket connect.
        After this, the browser receives only "delta" updates (new alerts, belief changes).
        
        CONTENTS OF SNAPSHOT
        ────────────────────
        {
          "type": "snapshot",
          "ts": 1234567890.5,
          "agent_beliefs": {
            "agent_a1": {"beliefs": {...}, "dominant": "...", ...},
            ...
          },
          "agent_trust": {
            "agent_a1": {"trust": 0.95, "status": "TRUSTED"},
            ...
          },
          "coord_beliefs": {...},
          "global_belief": {...},
          "recent_alerts": [...],   # Last 30 alerts (newest first)
          "backup_status": {...},
          "heartbeats": {...}
        }
        
        TECHNICAL NOTE
        ───────────────
        - Snapshot is one message (not split)
        - Sent immediately before entering live update stream
        - If queue full, silently drops (don't block, just skip this client)
        - Browser receives, parses as JSON, populates initial UI
        """
        snapshot = {
            "type":           "snapshot",
            "ts":             time.time(),
            "agent_beliefs":  self._agent_beliefs,
            "agent_trust":    self._agent_trust,
            "coord_beliefs":  self._coord_beliefs,
            "global_belief":  self._global_belief,
            "recent_alerts":  self._recent_alerts[:30],
            "backup_status":  self._backup_status,
            "heartbeats":     self._heartbeats,
        }
        try:
            q.put_nowait(json.dumps(snapshot, default=str))
        except asyncio.QueueFull:
            pass

    # ── State injection (called by trust manager / health monitor) ────────────

    def update_trust(self, node_id: str, trust: float, status: str) -> None:
        """
        Update trust score for a node (called externally by TrustManager).
        
        WHAT THIS DOES
        ──────────────
        TrustManager votes on whether a component is trustworthy (Byzantine voting).
        When consensus is reached, it calls this method to:
        1. Update internal _agent_trust tracking
        2. Create and broadcast a "trust_update" message to browsers
        
        This allows dashboard to show:
        - Green: TRUSTED (> 60% confidence)
        - Yellow: SUSPECT (30-60% confidence)  
        - Red: ISOLATED (< 30% confidence, won't process alerts)
        
        Parameters
        ──────────
        node_id : str
            Agent or coordinator being voted on (e.g., "agent_a1")
        trust : float
            Trust score 0.0-1.0 (usually from Byzantine voting results)
        status : str
            Status name: "TRUSTED", "SUSPECT", "ISOLATED", "OFFLINE"
        """
        self._agent_trust[node_id] = {"trust": round(trust, 3), "status": status}
        payload = json.dumps({
            "type":    "trust_update",
            "node_id": node_id,
            "trust":   round(trust, 3),
            "status":  status,
            "ts":      time.time(),
        })
        asyncio.create_task(self._broadcast(payload))

    def update_backup_status(self, backup_id: str, primary_id: str,
                              active: bool, reason: str = "") -> None:
        """
        Update backup coordinator status (called by HealthMonitor).
        
        WHAT THIS DOES
        ──────────────
        When a backup/proxy coordinator changes state (STANDBY → ACTIVE or vice versa),
        HealthMonitor calls this to:
        1. Update internal _backup_status tracking
        2. Broadcast "backup_status" message to dashboard
        
        Dashboard shows this as:
        - Blue STANDBY pill: Backup monitoring, ready if primary fails
        - Orange ACTIVE pulsing pill: Backup has taken over (primary is down)
        
        Example flow:
        - Primary coord_a is healthy → all backups show STANDBY
        - Primary coord_a crashes → HealthMonitor detects (no heartbeat)
        - HealthMonitor activates backup_coord_a → calls this function
        - Dashboard shows backup_coord_a is now ACTIVE (orange, pulsing)
        - Agents are redirected to contact backup_coord_a
        
        Parameters
        ──────────
        backup_id : str
            The backup/proxy server (e.g., "backup_coord_a")
        primary_id : str
            The primary server it backs up (e.g., "coord_a")
        active : bool
            True if backup is now active, False if back to standby
        reason : str
            Why the state changed (e.g., "Primary heartbeat timeout")
        """
        self._backup_status[backup_id] = {
            "primary_id": primary_id,
            "active": active,
            "reason": reason,
            "ts": time.time(),
        }
        payload = json.dumps({
            "type":       "backup_status",
            "backup_id":  backup_id,
            "primary_id": primary_id,
            "active":     active,
            "reason":     reason,
            "ts":         time.time(),
        })
        asyncio.create_task(self._broadcast(payload))

    # ── Properties for REST snapshot endpoint ─────────────────────────────────

    def get_state_snapshot(self) -> dict:
        """
        Get current system state as JSON-serializable dict.
        
        USED BY
        ───────
        - GET /api/state endpoint (REST API for state polling)
        - Initial snapshot for new WebSocket clients
        - Debugging: Can be downloaded/inspected
        
        RESPONSE STRUCTURE
        ──────────────────
        {
          "agent_beliefs": {
            "agent_a1": {
              "origin_id": "agent_a1",
              "beliefs": {
                "brute_force": 0.8234,
                "port_scan": 0.0156,
                ...
              },
              "max_p": 0.8234,        # Highest probability
              "threat_level": "HIGH"   # Name of dominant threat
            },
            ...
          },
          "agent_trust": {
            "agent_a1": {
              "trust": 0.95,       # 0.0-1.0 from Byzantine voting
              "status": "TRUSTED"  # TRUSTED/SUSPECT/ISOLATED/OFFLINE
            },
            ...
          },
          "coord_beliefs": {...},     # Coordinator beliefs
          "global_belief": {...},     # System-wide aggregated belief
          "recent_alerts": [...],     # Last 50 alerts (newest first)
          "backup_status": {...},     # Proxy/backup server states
          "heartbeats": {...},        # Last heartbeat timestamp per component
          "connected_clients": 2      # How many WebSocket browsers connected
        }
        
        This is essentially a "save state" of the system for display/inspection.
        """
        return {
            "agent_beliefs":  self._agent_beliefs,
            "agent_trust":    self._agent_trust,
            "coord_beliefs":  self._coord_beliefs,
            "global_belief":  self._global_belief,
            "recent_alerts":  self._recent_alerts[:50],
            "backup_status":  self._backup_status,
            "heartbeats":     self._heartbeats,
            "connected_clients": len(self._clients),
        }
