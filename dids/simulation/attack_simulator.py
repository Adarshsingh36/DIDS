"""
Simulation Framework — Creates fake attack scenarios for testing.

This file is like a movie stunt coordinator:
- It creates realistic but FAKE attacks
- Used to test if the security system detects them correctly
- Lets us verify the system works without real attackers

Instead of waiting for actual attacks (which might never come during testing),
we simulate them so we can verify our detection system is working.

SCENARIOS:
- brute_force_local: Many failed login attempts on one computer
- port_scan_sweep: Attacker probing for open ports
- ddos_distributed: High traffic attack across all regions
- mixed_attack: Multi-stage attack (recon → exploit → steal data)
- compromised_node: One agent sends misleading info
- run_all_scenarios: Test all of the above sequentially

Each scenario injects synthetic SecurityEvents into agents, which then
go through the normal detection pipeline. Good way to test!
"""

from __future__ import annotations
import asyncio
import logging
import random
import time
from typing import List

from dids.core.models import SecurityEvent
from dids.agents.monitoring_agent import MonitoringAgent

logger = logging.getLogger(__name__)


class AttackSimulator:
    """
    Injects security events into agents to simulate various attack scenarios.
    
    Instead of real network traffic, it directly creates SecurityEvent objects
    and feeds them to agents. This lets us:
    - Test without needing actual hackers
    - Run attacks at any time
    - Measure detection accuracy
    - Verify the system works end-to-end

    Parameters
    ----------
    agents : list of MonitoringAgent instances available for injection
    """

    def __init__(self, agents: List[MonitoringAgent]) -> None:
        self._agents = {a.agent_id: a for a in agents}

    # ------------------------------------------------------------------
    # Scenario runners - Different attack types to simulate
    # ------------------------------------------------------------------

    async def brute_force_local(self, target_agent_id: str,
                                count: int = 12, interval: float = 0.1) -> None:
        """
        Simulate a brute-force attack on one computer.
        
        Attacker scenario:
        - Repeatedly tries logging in with wrong passwords
        - Hopes to eventually guess right
        
        How we fake it:
        1. Generate 12 "failed_login" events from different IPs
        2. Send them to target agent's computer
        3. Then 1 "repeated_auth_failure" event (pattern recognition trigger)
        
        Expected result: System should detect brute force attack (>80% confidence)
        """
        logger.info("[Sim] brute_force_local → %s (%d events)", target_agent_id, count)
        agent = self._agents[target_agent_id]
        for _ in range(count):
            event = SecurityEvent.create(
                agent_id=target_agent_id,
                host_id=agent.host_id,
                event_type="failed_login",
                source_ip=f"192.168.{random.randint(1,5)}.{random.randint(1,254)}",
                payload={"username": "admin", "method": "ssh"},
            )
            await agent.ingest_event(event)
            await asyncio.sleep(interval)

        # Escalate to repeated auth failure
        event = SecurityEvent.create(
            agent_id=target_agent_id,
            host_id=agent.host_id,
            event_type="repeated_auth_failure",
            source_ip="192.168.1.99",
        )
        await agent.ingest_event(event)

    async def port_scan_sweep(self, agent_ids: List[str],
                              interval: float = 0.05) -> None:
        """
        Simulate an attacker scanning for open ports.
        
        Attack scenario:
        - Attacker sends connection attempts to many ports
        - Trying to find which services are running (reconnaissance)
        
        How we fake it:
        1. Create "port_scan_detected" events for multiple target agents
        2. Each with random ports to make it look realistic
        3. All from same attacker IP
        
        Expected result: System should detect port scan (>80% confidence)
        """
        logger.info("[Sim] port_scan_sweep → %s", agent_ids)
        scanner_ip = f"10.0.0.{random.randint(2, 254)}"
        for aid in agent_ids:
            agent = self._agents.get(aid)
            if not agent:
                continue
            for _ in range(5):
                event = SecurityEvent.create(
                    agent_id=aid,
                    host_id=agent.host_id,
                    event_type="port_scan_detected",
                    source_ip=scanner_ip,
                    payload={"ports": random.sample(range(1, 65535), 20)},
                )
                await agent.ingest_event(event)
                await asyncio.sleep(interval)

    async def ddos_distributed(self, interval: float = 0.08) -> None:
        """
        Simulate a DDoS (Distributed Denial of Service) attack.
        
        Attack scenario:
        - Massive traffic flood to overwhelm the network
        - Usually from many attacking computers
        - Goal: Make system unresponsive
        
        How we fake it:
        1. Send high-traffic events to ALL agents
        2. Multiple event types (SYN floods, ICMP floods, UDP floods)
        3. From varying attacker IPs
        
        Expected result: System should detect DDoS (>80% confidence on most agents)
        - Especially a DISTRIBUTED DDoS when global engine aggregates
        """
        logger.info("[Sim] ddos_distributed → all agents")
        agents = list(self._agents.values())
        for _ in range(8):
            for agent in agents:
                for etype in ("high_traffic_volume", "syn_flood", "icmp_flood"):
                    event = SecurityEvent.create(
                        agent_id=agent.agent_id,
                        host_id=agent.host_id,
                        event_type=etype,
                        source_ip=f"172.16.{random.randint(0,10)}.{random.randint(1,254)}",
                        payload={"pps": random.randint(50_000, 200_000)},
                    )
                    await agent.ingest_event(event)
            await asyncio.sleep(interval)

    async def mixed_attack(self, entry_agent_id: str,
                           exfil_agent_id: str) -> None:
        """
        Simulate a multi-stage Advanced Persistent Threat (APT).
        
        Attack scenario:
        - Stage 1: Reconnaissance (attacker gathers info about network)
        - Stage 2: Exploitation (attacker breaks into first system)
        - Stage 3: Lateral movement & data theft
        
        This is more realistic - real attackers use multiple steps.
        
        Expected result: Step-by-step detection as each stage progresses
        """
        logger.info("[Sim] mixed_attack: recon=%s exfil=%s",
                    entry_agent_id, exfil_agent_id)

        # Stage 1: reconnaissance (attacker scanns for vulnerabilities)
        await self.port_scan_sweep([entry_agent_id], interval=0.03)
        await asyncio.sleep(0.3)

        # Stage 2: exploitation (attacker breaks in and escalates privilege)
        entry_agent = self._agents[entry_agent_id]
        for etype in ("failed_login", "failed_login", "privilege_escalation",
                      "suspicious_process"):
            event = SecurityEvent.create(
                agent_id=entry_agent_id,
                host_id=entry_agent.host_id,
                event_type=etype,
                source_ip="10.10.10.50",
            )
            await entry_agent.ingest_event(event)
            await asyncio.sleep(0.05)

        await asyncio.sleep(0.3)

        # Stage 3: lateral movement + exfiltration (steal data and move around)
        exfil_agent = self._agents[exfil_agent_id]
        for etype in ("unusual_file_access", "outbound_data_spike",
                      "unusual_file_access", "outbound_data_spike"):
            event = SecurityEvent.create(
                agent_id=exfil_agent_id,
                host_id=exfil_agent.host_id,
                event_type=etype,
                source_ip="10.10.10.50",
                payload={"bytes_sent": random.randint(10_000_000, 500_000_000)},
            )
            await exfil_agent.ingest_event(event)
            await asyncio.sleep(0.05)

    async def run_all_scenarios(self, delay_between: float = 0.5) -> None:
        """
        Run all scenarios one after another.
        
        Convenience method for comprehensive testing.
        Good to run once to exercise the entire system.
        """
        agent_ids = list(self._agents.keys())
        if len(agent_ids) < 3:
            raise ValueError("Need at least 3 agents to run all scenarios")

        await self.brute_force_local(agent_ids[0])
        await asyncio.sleep(delay_between)

        await self.port_scan_sweep(agent_ids[:3])
        await asyncio.sleep(delay_between)

        await self.ddos_distributed()
        await asyncio.sleep(delay_between)

        await self.mixed_attack(agent_ids[0], agent_ids[-1])