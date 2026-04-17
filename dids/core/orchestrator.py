"""
DIDS Orchestrator — The "conductor" that sets up and manages the entire system.

Think of this like conducting an orchestra:
- Each agent is a musician
- Each coordinator is a section leader
- The orchestrator tells everyone when to start playing and what role to have

This file:
1. Creates all system components (agents, coordinators, backup coordinators, etc)
2. Wires them together on the message bus
3. Registers network callbacks
4. Starts everything in the right order
5. Gracefully shuts everything down

WITHOUT THIS FILE: You'd need to manually create each component and connect them.
WITH THIS FILE: "Just call build_and_start() and everything is ready."

IT'S A FACTORY - It builds the entire security system from configuration.
"""

from __future__ import annotations
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from dids.communication.bus import MessageBus
from dids.agents.monitoring_agent import MonitoringAgent
from dids.coordination.subdomain_coordinator import SubdomainCoordinator
from dids.coordination.backup_coordinator import BackupCoordinator
from dids.inference.global_engine import GlobalDetectionEngine
from dids.trust.trust_manager import DistributedTrustManager
from dids.admin.dashboard import AdminDashboard
from dids.core.health_monitor import HealthMonitor, NodePair

logger = logging.getLogger(__name__)


@dataclass
class SubdomainConfig:
    """
    Configuration for one security region.
    
    Example: "We're protecting 3 servers with 1 agent per server"
    """
    coordinator_id:  str        # Name of this region's coordinator
    host_ids:        List[str]  # Which computers to protect
    agents_per_host: int = 1    # How many agents monitor each host


@dataclass
class SystemConfig:
    """
    Configuration blueprint for the entire system.
    
    This controls what kind of system we build:
    - How many regions (subdomains) do we have?
    - Should we enable failover backups?
    - Should we capture live network packets?
    - How many trust managers for voting?
    
    Think of it like a restaurant blueprint:
    - How many sections? (subdomains)
    - Do we need backup hosts? (enable_backups)
    - Do we monitor the food quality? (enable_network_monitor)
    """
    subdomains:             List[SubdomainConfig] = field(default_factory=list)  # All security regions
    global_engine_id:       str  = "global_engine"        # System-wide analyzer
    trust_manager_id:       str  = "dtm_primary"          # Trust voting system
    dashboard_id:           str  = "admin_dashboard"      # Alert display
    num_trust_peers:        int  = 2                      # How many manage trust
    enable_backups:         bool = True                   # Hot-standby backup coordinators?
    enable_dashboard_tap:   bool = True                   # Real-time web monitoring?
    enable_network_monitor: bool = True                   # Live packet capture?
    monitor_interface:      Optional[str] = None          # Which network card to sniff?


def default_config() -> SystemConfig:
    """
    Create a sample configuration.
    
    This is the default setup - 3 regions with 3 computers each.
    Good for testing the whole system.
    """
    return SystemConfig(subdomains=[
        SubdomainConfig("coord_g0", ["h_a1", "h_a2", "h_a3"]),
        SubdomainConfig("coord_g1", ["h_b1", "h_b2", "h_b3"]),
        SubdomainConfig("coord_g2", ["h_c1", "h_c2", "h_c3"]),
    ], num_trust_peers=2)


class DIDSOrchestrator:
    """
    The conductor - sets up the entire security system.
    
    Call these methods:
    1. build_and_start() - Create everything and get it running
    2. Later: shutdown() - Clean stop everything gracefully
    
    That's it! The orchestrator handles all the internal management.
    """
    def __init__(self, config: Optional[SystemConfig] = None) -> None:
        self.config  = config or default_config()
        self.bus     = MessageBus()  # Central communication hub
        
        # All the components we'll create
        self.agents:          Dict[str, MonitoringAgent]      = {}  # Host-level guards
        self.coordinators:    Dict[str, SubdomainCoordinator] = {}  # Regional managers
        self.backup_coords:   Dict[str, BackupCoordinator]    = {}  # Standby backups
        self.global_engine:   Optional[GlobalDetectionEngine] = None  # System-wide analyzer
        self.trust_managers:  List[DistributedTrustManager]   = []  # Trust voters
        self.dashboard:       Optional[AdminDashboard]        = None  # Alert display
        self.health_monitor:  Optional[HealthMonitor]         = None  # Failover watchdog
        self.tap:             Optional[object]                = None  # Real-time monitoring
        self.network_monitor: Optional[object]                = None  # Packet sniffer

    async def build_and_start(self) -> None:
        """
        CREATE AND START THE ENTIRE SYSTEM.
        
        This is the main orchestration method. It:
        1. Creates the message bus and all components
        2. Connects them together logically
        3. Starts everything in the right order
        4. Registers network callbacks
        5. Starts the network monitor
        
        After this returns, the security system is fully operational.
        
        ORDER MATTERS:
        - Start dashboard first (nothing should happen before alerts can be received)
        - Start trust managers (they might be needed by global engine)
        - Start global engine (it receives beliefs from coordinators)
        - Start coordinators and backups (they receive messages from agents)
        - Start health monitor (it watches the coordinators)
        - Start agents (they generate events)
        - Start network monitor LAST (after all callbacks are registered)
        
        This cascade ensures nothing waits unnecessary or fails.
        """
        cfg = self.config

        if cfg.enable_dashboard_tap:
            from dids.web.tap import DashboardTap
            self.tap = DashboardTap(self.bus)

        self.dashboard = AdminDashboard(cfg.dashboard_id, self.bus)

        all_dtm = [cfg.trust_manager_id] + [f"dtm_peer_{i}" for i in range(cfg.num_trust_peers)]
        for did in all_dtm:
            self.trust_managers.append(
                DistributedTrustManager(did, [p for p in all_dtm if p != did], self.bus)
            )

        self.global_engine = GlobalDetectionEngine(
            engine_id=cfg.global_engine_id,
            trust_manager_id=cfg.trust_manager_id,
            dashboard_id=cfg.dashboard_id, bus=self.bus,
        )

        # Create NetworkMonitor BEFORE agents (register callbacks after)
        net_mon = None
        if cfg.enable_network_monitor:
            try:
                from dids.network.monitor import NetworkMonitor
                net_mon = NetworkMonitor(interface=cfg.monitor_interface)
                self.network_monitor = net_mon
            except Exception as e:
                logger.warning("NetworkMonitor init failed: %s", e)

        for sd in cfg.subdomains:
            coord = SubdomainCoordinator(
                coordinator_id=sd.coordinator_id,
                global_engine_id=cfg.global_engine_id, bus=self.bus,
            )
            self.coordinators[sd.coordinator_id] = coord
            sd_agents = []

            for host_id in sd.host_ids:
                for idx in range(sd.agents_per_host):
                    sfx      = host_id.split("_")[-1]
                    agent_id = f"agent_{sfx}_{idx}" if sd.agents_per_host > 1 else f"agent_{sfx}"
                    agent    = MonitoringAgent(agent_id, host_id, sd.coordinator_id, self.bus)
                    self.agents[agent_id] = agent
                    self.trust_managers[0].register_node(agent_id)
                    sd_agents.append(agent_id)

                    # Register this agent's callback with shared monitor
                    if net_mon:
                        net_mon.register_agent(agent_id, agent.on_network_event)

            if cfg.enable_backups:
                bid = f"{sd.coordinator_id}_backup"
                self.backup_coords[sd.coordinator_id] = BackupCoordinator(
                    backup_id=bid, primary_id=sd.coordinator_id,
                    global_engine_id=cfg.global_engine_id,
                    agent_ids=sd_agents, bus=self.bus,
                )

        if cfg.enable_backups:
            self.health_monitor = HealthMonitor(bus=self.bus, tap=self.tap)
            for sd in cfg.subdomains:
                if sd.coordinator_id in self.backup_coords:
                    self.health_monitor.register_pair(NodePair(
                        primary_id=sd.coordinator_id,
                        backup_id=f"{sd.coordinator_id}_backup",
                        primary_obj=self.coordinators[sd.coordinator_id],
                        backup_obj=self.backup_coords[sd.coordinator_id],
                    ))

        # Start order matters
        if self.tap:            await self.tap.start()
        await self.dashboard.start()
        for dtm in self.trust_managers:  await dtm.start()
        await self.global_engine.start()
        for c in self.coordinators.values():  await c.start()
        for b in self.backup_coords.values(): await b.start()
        if self.health_monitor: await self.health_monitor.start()
        for a in self.agents.values():        await a.start()

        # Start monitor AFTER all callbacks registered
        if net_mon:
            await net_mon.start()

        if self.tap and self.trust_managers:
            self._start_trust_sync()

        logger.info("[Orchestrator] Online: %d agents (all registered with monitor) | monitor=%s",
                    len(self.agents), "ON" if net_mon else "OFF")

    def _start_trust_sync(self) -> None:
        async def _sync():
            while True:
                await asyncio.sleep(2.0)
                if not self.trust_managers or not self.tap: continue
                for nid, info in self.trust_managers[0].trust_summary().items():
                    self.tap.update_trust(nid, info["trust"], info["status"])
        asyncio.create_task(_sync())

    async def shutdown(self) -> None:
        if self.network_monitor: self.network_monitor.stop()
        for a in self.agents.values():        await a.stop()
        for c in self.coordinators.values():  await c.stop()
        for b in self.backup_coords.values(): await b.stop()
        if self.global_engine:  await self.global_engine.stop()
        for dtm in self.trust_managers:       await dtm.stop()
        if self.dashboard:      await self.dashboard.stop()
        if self.tap:            await self.tap.stop()
        if self.health_monitor: await self.health_monitor.stop()
        logger.info("[Orchestrator] Shutdown.")

    def agent_ids(self) -> List[str]: return list(self.agents.keys())
    def get_proxy_status(self) -> List[dict]:
        return self.health_monitor.get_status() if self.health_monitor else []
    def get_monitor_status(self) -> dict:
        return self.network_monitor.get_status() if self.network_monitor else {
            "scapy_active": False, "psutil_active": False, "packets_seen": 0}