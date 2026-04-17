"""
Core Data Models — The "dictionary" of definitions used throughout the system.

This file defines all the basic data structures and enumerations (lists of choices).

Think of it like a airline baggage claim system:
- MessageType: Types of conversations (boarding call, seat assignment, baggage alert)
- ThreatLevel: Severity levels (Critical, High, Medium, Low, None)
- AttackType: Types of attacks we know about (Brute Force, Port Scan, DDoS, etc)
- SecurityEvent: A raw event we observed (like "3 failed logins")
- BeliefVector: Our belief about what's happening (80% DDoS, 15% Port Scan, 5% Other)
- Message: An envelope for communication between components
- AlertRecord: A confirmed security threat we're reporting
"""

from __future__ import annotations
import uuid
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations - Predefined lists of choices
# ---------------------------------------------------------------------------

class MessageType(Enum):
    """
    Types of messages that can be sent between components.
    
    Think of these as different kinds of conversations:
    - REGISTER: "I exist, please acknowledge me"
    - BELIEF_UPDATE: "Here's my current opinion about what's happening"
    - QUERY: "What do you think is happening?"
    - ALERT: "I'm confident we're under attack!"
    - HEARTBEAT: "I'm still alive"
    - TRUST_VERIFY: "Is this other node trustworthy?"
    """
    REGISTER        = "REGISTER"
    EVENT           = "EVENT"
    BELIEF_UPDATE   = "BELIEF_UPDATE"
    QUERY           = "QUERY"
    ALERT           = "ALERT"
    TRUST_VERIFY    = "TRUST_VERIFY"
    TRUST_VOTE      = "TRUST_VOTE"
    HEARTBEAT       = "HEARTBEAT"
    ACK             = "ACK"


class ThreatLevel(Enum):
    """
    Severity levels for security threats.
    
    Like a fire alarm system:
    - NONE: No threat detected
    - LOW: Suspicious but probably harmless
    - MEDIUM: Getting serious, should investigate
    - HIGH: Serious threat, take action now
    - CRITICAL: Immediate danger, all hands on deck!
    """
    NONE     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4


class NodeStatus(Enum):
    """
    Trust status of a component (is it trustworthy?).
    
    - TRUSTED: This component is behaving normally
    - SUSPECT: This component might be compromised or malfunctioning
    - ISOLATED: This component is definitely bad, cut it off
    - OFFLINE: This component is not responding / dead
    """
    TRUSTED    = auto()
    SUSPECT    = auto()
    ISOLATED   = auto()
    OFFLINE    = auto()


class AttackType(Enum):
    """
    Types of security attacks the system recognizes.
    
    - BRUTE_FORCE: Attacker trying many passwords (like trying every key on a lock)
    - PORT_SCAN: Attacker scanning for open ports (reconnaissance)
    - DDOS: Attacker flooding network with traffic (Distributed Denial of Service)
    - PRIVILEGE_ESCAL: Attacker gaining admin rights
    - DATA_EXFIL: Attacker stealing data
    - MALWARE: Malicious software on a computer
    """
    UNKNOWN          = "unknown"
    BRUTE_FORCE      = "brute_force"
    PORT_SCAN        = "port_scan"
    DDOS             = "ddos"
    PRIVILEGE_ESCAL  = "privilege_escalation"
    DATA_EXFIL       = "data_exfiltration"
    MALWARE          = "malware"


# ---------------------------------------------------------------------------
# Raw event - What we directly observe
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecurityEvent:
    """
    A raw security event observed on the network or at a host.
    
    Think of this like a security camera recording:
    - "Time 14:23:45, camera 5 detected: failed login attempt from 192.168.1.100"
    
    This is the raw input. We don't make conclusions yet, just record what happened.
    
    frozen=True means once created, this event can't be changed (immutable).
    """
    event_id:   str = ""              # Unique ID for this event
    agent_id:   str = ""              # Which agent saw this event
    host_id:    str = ""              # Which computer this happened on
    timestamp:  float = 0.0           # When it happened
    event_type: str = ""              # What kind of event (e.g., "failed_login")
    source_ip:  Optional[str] = None  # Which IP address was involved
    payload:    Dict[str, Any] = field(default_factory=dict)  # Extra details

    @staticmethod
    def create(agent_id: str, host_id: str, event_type: str,
               source_ip: Optional[str] = None,
               payload: Optional[Dict[str, Any]] = None) -> "SecurityEvent":
        """
        Factory function to create a new event.
        
        This is a convenience method that fills in:
        - A unique ID
        - Current timestamp
        
        So you only need to provide the important details.
        """
        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            agent_id=agent_id,
            host_id=host_id,
            timestamp=time.time(),
            event_type=event_type,
            source_ip=source_ip,
            payload=payload or {},
        )


# ---------------------------------------------------------------------------
# Belief Vector - Our opinion about what's happening
# ---------------------------------------------------------------------------

@dataclass
class BeliefVector:
    """
    A probability distribution of what attack (if any) is happening.
    
    Think of it like a weatherman's forecast:
    "There's an 80% chance of DDoS, 15% chance of multiple attacks, 5% no attack"
    
    Values don't have to sum to exactly 1.0 - the remainder is "probably no attack".
    """
    origin_id:  str = ""              # Which component created this belief
    timestamp:  float = field(default_factory=time.time)  # When was this created
    beliefs:    Dict[str, float] = field(default_factory=dict)  # Attack type -> probability

    def dominant_threat(self) -> AttackType:
        """What attack type do we think is most likely?"""
        if not self.beliefs:
            return AttackType.UNKNOWN
        best = max(self.beliefs, key=self.beliefs.get)
        return AttackType(best)

    def max_probability(self) -> float:
        """What's our confidence level (0.0 to 1.0)?"""
        return max(self.beliefs.values(), default=0.0)

    def threat_level(self) -> ThreatLevel:
        """
        Convert our confidence into a severity level.
        
        Higher confidence = higher threat level
        - 0-20%: No threat
        - 20-45%: Low
        - 45-65%: Medium
        - 65-85%: High  
        - 85-100%: Critical
        """
        p = self.max_probability()
        if p < 0.20:  return ThreatLevel.NONE
        if p < 0.45:  return ThreatLevel.LOW
        if p < 0.65:  return ThreatLevel.MEDIUM
        if p < 0.85:  return ThreatLevel.HIGH
        return ThreatLevel.CRITICAL


# ---------------------------------------------------------------------------
# Alert Record - A confirmed threat we're reporting
# ---------------------------------------------------------------------------

@dataclass
class AlertRecord:
    """
    An official security alert - "Something bad is probably happening!"
    
    This is raised when we're confidence enough that an attack is occurring.
    
    Think of it like a fire alarm:
    - It includes WHERE the fire is (source_node, involved_ips)
    - HOW BAD it is (threat_level)
    - WHAT TYPE it is (attack_type)
    - WHY we think so (evidence - the events that led to this conclusion)
    """
    alert_id:     str = field(default_factory=lambda: str(uuid.uuid4()))  # Unique ID
    timestamp:    float = field(default_factory=time.time)  # When was this alert created
    source_node:  str = ""            # Which agent/coordinator raised this alert
    attack_type:  AttackType = AttackType.UNKNOWN  # What kind of attack
    probability:  float = 0.0         # Confidence level (0.0 to 1.0)
    threat_level: ThreatLevel = ThreatLevel.NONE  # Severity (CRITICAL/HIGH/MEDIUM/LOW/NONE)
    involved_ips: List[str] = field(default_factory=list)  # IPs involved in the attack
    evidence:     List[str] = field(default_factory=list)  # Event IDs that led to alert

    def __str__(self) -> str:
        """Pretty-print this alert for display."""
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        return (f"[ALERT {self.alert_id[:8]}] {ts} | "
                f"{self.threat_level.name} | {self.attack_type.value} | "
                f"p={self.probability:.2f} | src={self.source_node}")


# ---------------------------------------------------------------------------
# Message Envelope - Container for all inter-node communication
# ---------------------------------------------------------------------------

@dataclass
class Message:
    """
    An envelope for communication between components.
    
    Think of it like a postal letter:
    - msg_id: Tracking number
    - sender: From whom
    - receiver: To whom
    - msg_type: What kind of message (letter, package, postcard, etc)
    - payload: The actual contents
    
    If receiver is empty, it's a broadcast (delivered to everyone).
    """
    msg_id:   str = field(default_factory=lambda: str(uuid.uuid4()))
    msg_type: MessageType = MessageType.EVENT
    sender:   str = ""
    receiver: str = ""          # Empty = broadcast
    timestamp: float = field(default_factory=time.time)
    payload:  Any = None        # The actual message content

    def ack(self) -> "Message":
        """Create an acknowledgement message (like "message received")."""
        return Message(msg_type=MessageType.ACK,
                       sender=self.receiver,
                       receiver=self.sender,
                       payload={"ack_for": self.msg_id})
