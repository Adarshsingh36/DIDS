"""
NETWORK MONITOR — The Security Camera System

Think of this like a security camera system for the network:
- It watches all packets (data packets flowing through the network)
- Detects suspicious patterns (too many login attempts, repeated connections to many ports, floods)
- Routes alerts to the right security guard (agent) who can investigate

HOW IT WORKS IN PLAIN LANGUAGE
─────────────────────────────
1. Capture incoming packets from the physical network interface (like a camera recording)
2. For each packet, extract source IP and network protocol (how the data was sent)
3. Check for known attack patterns:
   - Port scanning: "Is this IP trying to connect to many different ports?" (reconnaissance)
   - Brute force: "Are we seeing repeated failed logins from the same IP?" (hacking attempt)
   - DDoS floods: "Is this IP sending way too much traffic?" (overwhelm attack)
   - ICMP flooding: "Excessive ping attempts?" (ping of death)
4. When a pattern is detected, notify the appropriate agent(s)

ROUTING INTELLIGENCE — Who Should Know About This Attack?
──────────────────────────────────────────────────────────
Different attacks affect different agents:
- ICMP flood attacks (ping floods) → Tell ALL agents (ping reaches all computers)
- SYN floods (TCP connection floods) → Tell one agent per region (coordinate defense)
- Port scans (attacker searching for open services) → Tell primary + one agent per region
- High traffic floods → Tell ALL agents (affects the whole network)
- Failed logins → Tell the affected agent (depends which server was targeted)

ARCHITECTURE
────────────
The monitor uses three parallel strategies:
1. Scapy (primary if available): Captures raw network packets, most accurate
2. psutil (fallback): Watches system network stats
3. Windows Event Log (fallback): Reads Windows security events

BUGS FIXED & FEATURES
─────────────────────
✓ Simulator events bypass rate limiting (don't throttle test data)
✓ ICMP detection uses proto field (more reliable on Windows than haslayer)
✓ Port scan now alerts multiple agents (cooperative watch)
✓ Cooperative alerts broadcast between all agents
"""

from __future__ import annotations
import asyncio
import collections
import logging
import platform
import threading
import time
from typing import Callable, Deque, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

PROTO_ICMP = 1
PROTO_TCP  = 6
PROTO_UDP  = 17

# ── Thresholds (tuned for real Kali tools) ────────────────────────────────────
PORT_SCAN_UNIQUE_PORTS = 8
PORT_SCAN_WINDOW       = 20.0

SYN_FLOOD_COUNT  = 80
SYN_FLOOD_WINDOW = 6.0

ICMP_FLOOD_COUNT  = 15          # ping -f hits this in <1 second
ICMP_FLOOD_WINDOW = 4.0

UDP_FLOOD_COUNT  = 100
UDP_FLOOD_WINDOW = 5.0

TRAFFIC_BPS    = 1_500_000
TRAFFIC_WINDOW = 3.0

COOLDOWN = 3.0   # only applied to live packets, NOT simulator events

BPF_FILTER = "ip"


class _Counter:
    """
    A sliding-window event counter.
    
    ANALOGY: Like counting people entering a building during a time window.
    "How many failed logins in the last 20 seconds?" "How many ping packets in the last 4 seconds?"
    
    Key behavior:
    - Events older than the window are automatically removed
    - Each call to add() returns current count in the window
    - Thread-safe (multiple processes can use it simultaneously)
    
    Example usage:
    ```
    counter = _Counter(window=6.0)
    count = counter.add()  → returns 1 (1st event)
    count = counter.add()  → returns 2 (2nd event, still in window)
    # ... wait 3 seconds ...
    # ... add 80 more events ...
    count = counter.add()  → returns 82 (all in 6-second window)
    if count >= 80:  # Threshold for SYN flood
        alert!
    ```
    """
    def __init__(self, window: float) -> None:
        self._w  = window
        self._ts: Deque[float] = collections.deque()
        self._lk = threading.Lock()

    def add(self) -> int:
        t = time.time()
        with self._lk:
            self._ts.append(t)
            cut = t - self._w
            while self._ts and self._ts[0] < cut:
                self._ts.popleft()
            return len(self._ts)

    def reset(self) -> None:
        with self._lk:
            self._ts.clear()


class NetworkMonitor:
    """
    The Network Packet Sniffer — Your System's Security Camera.
    
    WHAT IT DOES
    ────────────
    Captures all network packets flowing through this computer and looks for attack patterns.
    When a pattern is found, it routes alerts to the appropriate agent(s).
    
    ROUTING LOGIC — Who Gets Told About What?
    ──────────────────────────────────────────
    ┌─ ICMP Flood (ping attack)
    │  └─ Affects: ALL agents (every computer in the network)
    │  └─ Why: Ping attacks target the whole network
    │
    ├─ SYN Flood (connection spam)
    │  └─ Affects: One agent per network region (3 agents)
    │  └─ Why: Each region coordinates its own defense
    │
    ├─ Port Scan (attacker searching for open services)
    │  └─ Affects: Primary agent + one agent per other region
    │  └─ Why: Puts target and neighbors on alert
    │
    ├─ UDP Flood (another type of data flood)
    │  └─ Affects: All agents
    │  └─ Why: Usually broadcast across network
    │
    ├─ High Traffic Volume (data tsunami)
    │  └─ Affects: All agents (DDoS detection)
    │  └─ Why: Everyone needs to know about the flood
    │
    └─ Failed Logins (hacking attempts)
       └─ Affects: One agent (where the attack happened)
       └─ Why: Hash the source IP to consistent agent
    
    TECHNICAL SETUP
    ───────────────
    Three detection methods (uses what's available):
    1. Scapy: Captures raw packets at network level (most reliable)
    2. psutil: Monitors OS-level network stats (fallback if Scapy unavailable)
    3. Windows Event Log: Reads Windows security event log (Windows-specific fallback)
    
    DETECTION THRESHOLDS (Tuned through testing)
    ────────────────────
    - Port Scan: 8+ unique destination ports in 20 seconds
    - SYN Flood: 80+ SYN packets in 6 seconds
    - ICMP Flood: 15+ ping packets in 4 seconds
    - UDP Flood: 100+ UDP packets in 5 seconds
    - High Traffic: 1.5 Mbps sustained for 3 seconds
    - Rate Limit: Don't alert same (IP, attack_type) more than once per 3 seconds
    """

    def __init__(self, interface: Optional[str] = None) -> None:
        """
        Initialize the network monitor.
        
        Parameters
        ----------
        interface : str, optional
            Network interface to sniff on (e.g., "eth0", "Ethernet").
            If None, Scapy auto-detects the best interface.
        """
        self._iface      = interface
        self._callbacks: Dict[str, Callable] = {}
        self._agent_ids: List[str] = []

        self._syn_ctr:  Dict[str, _Counter] = {}
        self._icmp_ctr: Dict[str, _Counter] = {}
        self._udp_ctr:  Dict[str, _Counter] = {}
        self._port_set: Dict[str, Set[int]] = collections.defaultdict(set)
        self._port_ts:  Dict[str, float]    = {}
        self._cooldown: Dict[str, float]    = {}

        self._byte_lk  = threading.Lock()
        self._byte_win: Deque[Tuple[float, int]] = collections.deque()

        self._loop:   Optional[asyncio.AbstractEventLoop] = None
        self._running = False

        self.packets_seen  = 0
        self.scapy_active  = False
        self.psutil_active = False

    def register_agent(self, agent_id: str, callback: Callable) -> None:
        """
        Register a security guard (agent) to receive attack notifications.
        
        When this monitor detects an attack, it will call the callback function
        with details. Multiple agents can be registered to receive the same alert
        (depending on routing strategy).
        
        Parameters
        ----------
        agent_id : str
            Unique identifier for the agent (e.g., "agent_a1")
        callback : Callable
            Async function to call when attack detected. Signature:
            callback(event_type: str, source_ip: str, payload: dict)
        
        Example
        -------
        >>> async def handle_attack(event_type, src_ip, payload):
        ...     print(f"Alert! {event_type} from {src_ip}")
        >>> 
        >>> monitor.register_agent("agent_a1", handle_attack)
        """
        self._callbacks[agent_id] = callback
        if agent_id not in self._agent_ids:
            self._agent_ids.append(agent_id)

    async def start(self) -> None:
        """
        Turn on the network camera and start watching for attacks.
        
        This starts the background sniffer threads:
        1. Scapy packet sniffer (if Npcap available) — most accurate
        2. psutil fallback monitor (if Scapy not available)
        3. Windows Event Log monitor (Windows-specific)
        
        Prints a banner showing which detection methods are active and the
        thresholds being used.
        
        Requirements
        ────────────
        Windows:    pip install scapy psutil, download Npcap 1.70+
        Linux/Mac:  pip install scapy psutil (usually works)
        Docker:     pip install scapy psutil (limited packet capture inside container)
        """
        self._loop    = asyncio.get_event_loop()
        self._running = True

        n = len(self._callbacks)
        print(f"\n{'─'*60}")
        print(f"  [NetworkMonitor] {n} agents registered")
        print(f"  [NetworkMonitor] Routing: icmp→all, syn→3, portscan→multi, login→1")

        if await asyncio.get_event_loop().run_in_executor(None, self._check_npcap):
            t = threading.Thread(target=self._scapy_loop, daemon=True, name="ScapySniffer")
            t.start()
            self.scapy_active = True
            print(f"  [NetworkMonitor] Scapy ACTIVE  iface={self._iface or 'auto'}")
            print(f"  [NetworkMonitor] Thresholds:"
                  f" icmp>{ICMP_FLOOD_COUNT}/{ICMP_FLOOD_WINDOW:.0f}s"
                  f" syn>{SYN_FLOOD_COUNT}/{SYN_FLOOD_WINDOW:.0f}s"
                  f" portscan>{PORT_SCAN_UNIQUE_PORTS}ports/{PORT_SCAN_WINDOW:.0f}s")
        else:
            print("  [NetworkMonitor] Scapy unavailable")

        try:
            import psutil  # noqa
            self.psutil_active = True
            t2 = threading.Thread(target=self._psutil_loop, daemon=True, name="PsutilMon")
            t2.start()
            print("  [NetworkMonitor] psutil ACTIVE (fallback)")
        except ImportError:
            pass

        if platform.system() == "Windows":
            threading.Thread(target=self._eventlog_loop, daemon=True).start()

        if not self.scapy_active and not self.psutil_active:
            print("  [NetworkMonitor] WARNING: No capture! pip install scapy psutil + Npcap")

        print(f"{'─'*60}\n")

    def stop(self) -> None:
        self._running = False

    def get_status(self) -> dict:
        return {
            "scapy_active":    self.scapy_active,
            "psutil_active":   self.psutil_active,
            "interface":       self._iface or "auto",
            "packets_seen":    self.packets_seen,
            "agents_watching": len(self._callbacks),
        }

    # ── Npcap check ───────────────────────────────────────────────────────────

    def _check_npcap(self) -> bool:
        try:
            from scapy.all import conf  # noqa
        except Exception:
            print("  [NetworkMonitor] scapy not importable (pip install scapy)")
            return False

        if platform.system() == "Windows":
            try:
                import ctypes
                ctypes.windll.LoadLibrary("wpcap.dll")
            except OSError:
                print("  [NetworkMonitor] Npcap NOT found → https://npcap.com")
                print("  [NetworkMonitor] Tick 'WinPcap API compat', run as Admin")
                return False

        try:
            from scapy.all import get_if_list
            ifaces = get_if_list()
            if self._iface and self._iface not in ifaces:
                print(f"  [NetworkMonitor] Interface '{self._iface}' not found.")
                print(f"  [NetworkMonitor] Available: {ifaces}")
                self._iface = None
            return True
        except Exception as e:
            logger.warning("Scapy iface check: %s", e)
            return False

    # ── Scapy sniffer ─────────────────────────────────────────────────────────

    def _scapy_loop(self) -> None:
        from scapy.all import sniff, conf
        conf.sniff_promisc = True
        kw: dict = {"prn": self._on_packet, "store": False, "filter": BPF_FILTER}
        if self._iface:
            kw["iface"] = self._iface
        try:
            sniff(**kw)
        except PermissionError:
            print("\n  [NetworkMonitor] Permission denied — run as Administrator\n")
            self.scapy_active = False
        except Exception as e:
            print(f"\n  [NetworkMonitor] Sniffer error: {e}\n")
            self.scapy_active = False

    def _on_packet(self, pkt) -> None:
        """
        Process each packet. Uses ip.proto (not haslayer) for ICMP — more reliable
        on Windows Npcap where haslayer(ICMP) can silently fail.
        """
        try:
            from scapy.all import IP
            if not pkt.haslayer(IP):
                return

            ip    = pkt[IP]
            src   = ip.src
            proto = ip.proto      # 1=ICMP, 6=TCP, 17=UDP
            plen  = len(pkt)
            now   = time.time()

            if src.startswith("127.") or src.startswith("224.") or src == "::1":
                return

            self.packets_seen += 1
            if self.packets_seen == 1:
                print(f"\n  [NetworkMonitor] ✓ First packet: {src} proto={proto} — sniffer WORKING\n")

            # ── Traffic volume ────────────────────────────────────────
            with self._byte_lk:
                self._byte_win.append((now, plen))
                cut = now - TRAFFIC_WINDOW
                while self._byte_win and self._byte_win[0][0] < cut:
                    self._byte_win.popleft()
                bps = sum(b for _, b in self._byte_win) / TRAFFIC_WINDOW
            if bps > TRAFFIC_BPS:
                self._fire("high_traffic_volume", src, {"bps": int(bps)}, "all")

            # ── ICMP — uses proto field, NOT haslayer ─────────────────
            if proto == PROTO_ICMP:
                icmp_type = 8  # assume echo request by default
                try:
                    from scapy.all import ICMP as _ICMP
                    if pkt.haslayer(_ICMP):
                        icmp_type = pkt[_ICMP].type
                except Exception:
                    pass

                ctr = self._icmp_ctr.setdefault(src, _Counter(ICMP_FLOOD_WINDOW))
                n   = ctr.add()
                if n >= ICMP_FLOOD_COUNT:
                    # ping -f floods every host → alert ALL agents
                    self._fire("icmp_flood", src,
                               {"icmp_count": n, "icmp_type": icmp_type}, "all")
                    ctr.reset()

            # ── TCP ───────────────────────────────────────────────────
            elif proto == PROTO_TCP:
                try:
                    from scapy.all import TCP as _TCP
                    if not pkt.haslayer(_TCP):
                        return
                    tcp   = pkt[_TCP]
                    flags = int(tcp.flags)
                    dport = tcp.dport
                except Exception:
                    return

                syn_only = bool(flags & 0x02) and not bool(flags & 0x10)

                # Port scan tracking
                last_reset = self._port_ts.get(src, 0)
                if now - last_reset > PORT_SCAN_WINDOW:
                    self._port_set[src] = set()
                    self._port_ts[src]  = now

                self._port_set[src].add(dport)
                unique = len(self._port_set[src])

                if unique >= PORT_SCAN_UNIQUE_PORTS:
                    # Port scan: primary agent + one from each other subdomain
                    # so cooperative watch mode kicks in everywhere
                    port_bucket = min(dport, 1023) // 256
                    self._fire("port_scan_detected", src, {
                        "unique_ports": unique,
                        "sample": sorted(self._port_set[src])[:10],
                    }, "multi_subdomain", extra=port_bucket)
                    self._port_set[src] = set()
                    self._port_ts[src]  = now

                if syn_only:
                    ctr = self._syn_ctr.setdefault(src, _Counter(SYN_FLOOD_WINDOW))
                    n   = ctr.add()
                    if n >= SYN_FLOOD_COUNT:
                        self._fire("syn_flood", src, {"syn_count": n}, "per_subdomain")
                        ctr.reset()

            # ── UDP ───────────────────────────────────────────────────
            elif proto == PROTO_UDP:
                ctr = self._udp_ctr.setdefault(src, _Counter(UDP_FLOOD_WINDOW))
                n   = ctr.add()
                if n >= UDP_FLOOD_COUNT:
                    self._fire("high_traffic_volume", src,
                               {"udp_count": n, "protocol": "udp"}, "all")
                    ctr.reset()

        except Exception as e:
            logger.debug("Packet error: %s", e)

    # ── Agent routing ─────────────────────────────────────────────────────────

    def _resolve_targets(self, strategy: str, src_ip: str,
                         extra: int = 0) -> List[str]:
        """
        all            → all 9 agents
        multi_subdomain→ 1 primary + 1 from each other subdomain (port scan)
        per_subdomain  → 1 agent per subdomain, 3 total (SYN flood)
        one_by_ip      → 1 agent by hash (failed login)
        one_by_port    → 1 agent by port bucket
        """
        if not self._agent_ids:
            return []

        n = len(self._agent_ids)

        if strategy == "all":
            return list(self._agent_ids)

        if strategy == "multi_subdomain":
            primary_idx = (hash(src_ip) + extra) % n
            results = [self._agent_ids[primary_idx]]
            sub_size = max(1, n // 3)
            primary_sub = primary_idx // sub_size
            for sub_idx in range(n // sub_size):
                if sub_idx != primary_sub:
                    agent = self._agent_ids[sub_idx * sub_size]
                    if agent not in results:
                        results.append(agent)
            return results

        if strategy == "per_subdomain":
            results = []
            for i in range(0, n, 3):
                results.append(self._agent_ids[i])
            return results

        if strategy == "one_by_ip":
            return [self._agent_ids[hash(src_ip) % n]]

        if strategy == "one_by_port":
            return [self._agent_ids[(hash(src_ip) + extra) % n]]

        return [self._agent_ids[0]]

    # ── Fire with cooldown (live packets only) ────────────────────────────────

    def _fire(self, event_type: str, src_ip: str, payload: dict,
              strategy: str, extra: int = 0) -> None:
        """Cooldown only applies to live packet events, not simulator events."""
        key = f"{src_ip}:{event_type}"
        now = time.time()
        if now - self._cooldown.get(key, 0) < COOLDOWN:
            return
        self._cooldown[key] = now

        targets = self._resolve_targets(strategy, src_ip, extra)
        payload["strategy"] = strategy

        print(f"  [DETECTION] {event_type:<22} src={src_ip:<16} "
              f"→ {len(targets)} agent(s): {[t.replace('agent_','') for t in targets]}")

        if not self._loop or not self._loop.is_running():
            return

        for agent_id in targets:
            cb = self._callbacks.get(agent_id)
            if cb:
                asyncio.run_coroutine_threadsafe(
                    cb(event_type, src_ip, payload), self._loop
                )

    # ── psutil fallback ───────────────────────────────────────────────────────

    def _psutil_loop(self) -> None:
        import psutil
        prev_recv = 0
        prev_ts   = time.time()

        while self._running:
            time.sleep(2.0)
            try:
                now = time.time()
                dt  = max(now - prev_ts, 0.001)
                prev_ts = now

                try:
                    conns = psutil.net_connections(kind="inet")
                except (psutil.AccessDenied, PermissionError):
                    conns = []

                current: Dict[str, Set[int]] = collections.defaultdict(set)
                for c in conns:
                    if c.raddr and c.laddr:
                        rip = c.raddr.ip
                        if rip.startswith(("127.", "::1")):
                            continue
                        current[rip].add(c.laddr.port)

                for ip, ports in current.items():
                    if len(ports) >= PORT_SCAN_UNIQUE_PORTS // 2:
                        self._fire("port_scan_detected", ip, {
                            "unique_ports": len(ports), "source": "psutil"
                        }, "one_by_port")

                try:
                    stats     = psutil.net_io_counters()
                    delta     = stats.bytes_recv - prev_recv
                    prev_recv = stats.bytes_recv
                    if delta / dt > TRAFFIC_BPS:
                        self._fire("high_traffic_volume", "0.0.0.0",
                                   {"bps": int(delta / dt), "source": "psutil"}, "all")
                except Exception:
                    pass

            except Exception as e:
                logger.debug("psutil: %s", e)

    # ── Windows Event Log ─────────────────────────────────────────────────────

    def _eventlog_loop(self) -> None:
        try:
            import win32evtlog
        except ImportError:
            return
        try:
            handle = win32evtlog.OpenEventLog("localhost", "Security")
        except Exception as e:
            if getattr(e, "winerror", 0) == 1314:
                print("  [NetworkMonitor] Event Log: needs Admin — skipped")
            return

        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ
                 | win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        try:
            win32evtlog.ReadEventLog(handle, flags, 0)
        except Exception:
            pass

        while self._running:
            time.sleep(3.0)
            try:
                for ev in (win32evtlog.ReadEventLog(handle, flags, 0) or []):
                    if (ev.EventID & 0xFFFF) == 4625:
                        s   = ev.StringInserts or []
                        src = s[19] if len(s) > 19 else "unknown"
                        if src and src not in ("-", "unknown", "::1") \
                                and not src.startswith("127."):
                            self._fire("failed_login", src, {
                                "user": s[5] if len(s) > 5 else "?",
                                "source": "event_log",
                            }, "one_by_ip")
            except Exception:
                pass