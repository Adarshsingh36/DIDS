"""
main.py — Starting point for the DIDS (Distributed Intrusion Detection System) application.

This file is the entry point for the entire security system. It prepares and launches either:
  1. A web-based dashboard (Server mode) - shows real-time security alerts in a browser
  2. A command-line testing tool (CLI mode) - simulates attacks to test the system

Example commands to run:
  - Start web server:    python -m dids.main --serve --port 8000
  - Test with simulation: python -m dids.main --scenario brute

This file does NOT do the actual security detection - it just starts the system and lets
the user choose what to do with it (view a dashboard or run a test scenario).
"""

from __future__ import annotations
import argparse, asyncio, logging, os, sys
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))
from dids.core.orchestrator import DIDSOrchestrator, default_config
from dids.simulation.attack_simulator import AttackSimulator


def configure_logging(verbose: bool = False) -> None:
    """
    Set up logging output.
    
    This controls what messages appear in the console.
    - If verbose=True: Shows DEBUG messages (very detailed)
    - If verbose=False: Shows only WARNING messages (high-level issues)
    
    Example: If an error happens, we want to know about it in the console.
    """
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%H:%M:%S")
    for n in ("dids.core.orchestrator","dids.network.monitor",
              "dids.core.health_monitor","dids.agents.monitoring_agent"):
        logging.getLogger(n).setLevel(logging.INFO)


async def run_cli(scenario, verbose, interface, no_monitor):
    """
    Command-line mode: Runs security tests and shows results in the terminal.
    
    This function:
    1. Starts the entire security system
    2. Simulates an attack (brute force, port scan, DDoS, or mixed attack)
    3. Prints results showing what was detected
    4. Stops the system
    
    Think of it like a test to verify the security system is working correctly.
    You can pick which type of attack to simulate (--scenario brute, --scenario scan, etc).
    """
    configure_logging(verbose)
    print("\n" + "="*70)
    print("  DIDS — Distributed Intrusion Detection System")
    print("="*70 + "\n")

    cfg = default_config()
    cfg.enable_network_monitor = not no_monitor
    cfg.monitor_interface      = interface

    orch = DIDSOrchestrator(cfg)
    await orch.build_and_start()
    await asyncio.sleep(0.5)

    mon = orch.get_monitor_status()
    if mon.get("scapy_active"):
        print(f"  LIVE DETECTION: Scapy ACTIVE — {mon['agents_watching']} agents watching\n")
    elif mon.get("psutil_active"):
        print(f"  LIVE DETECTION: psutil ACTIVE — {mon['agents_watching']} agents\n")
    else:
        print("  SIMULATION ONLY — no live capture\n")

    aids = orch.agent_ids()
    sim  = AttackSimulator(list(orch.agents.values()))
    print(f"Scenario: '{scenario}'\n")

    if scenario == "brute":   await sim.brute_force_local(aids[0])
    elif scenario == "scan":  await sim.port_scan_sweep(aids[:4])
    elif scenario == "ddos":  await sim.ddos_distributed()
    elif scenario == "mixed": await sim.mixed_attack(aids[0], aids[-1])
    else:                     await sim.run_all_scenarios(delay_between=0.4)

    await asyncio.sleep(2.0)
    orch.dashboard.print_summary()
    print("Trust scores:")
    for nid, info in sorted(orch.trust_managers[0].trust_summary().items()):
        print(f"  {nid:<20} [{'█'*int(info['trust']*20):<20}] {info['trust']:.2f}  {info['status']}")
    if orch.backup_coords:
        print("\nProxy servers:")
        for _, b in orch.backup_coords.items():
            print(f"  {b.backup_id:<28} {b.status}")
    print()
    await orch.shutdown()


def run_server(port, host, interface, no_monitor):
    """
    Server mode: Starts a web dashboard that runs continuously.
    
    This creates a website that you can open in your browser to:
    - See live security alerts as they happen
    - Monitor the health of different parts of the system
    - Manually trigger test attacks
    
    The server runs indefinitely until you stop it (Ctrl+C).
    Default URL: http://localhost:8000
    """
    try:
        import uvicorn
    except ImportError:
        print("pip install fastapi uvicorn websockets"); sys.exit(1)

    os.environ["DIDS_MONITOR_INTERFACE"] = interface or ""
    os.environ["DIDS_NO_MONITOR"]        = "1" if no_monitor else "0"

    print("\n" + "="*70)
    print("  DIDS Security Operations Center")
    print(f"  http://{host if host != '0.0.0.0' else 'localhost'}:{port}")
    print(f"  Live capture: {'OFF' if no_monitor else 'ON  iface=' + (interface or 'auto')}")
    print("  Ctrl+C to stop")
    print("="*70 + "\n")
    uvicorn.run("dids.web.server:app", host=host, port=port,
                reload=False, log_level="warning")


def main():
    p = argparse.ArgumentParser()
    m = p.add_mutually_exclusive_group()
    m.add_argument("--serve",    action="store_true")
    m.add_argument("--scenario", choices=["all","brute","scan","ddos","mixed"], default="all")
    p.add_argument("--port",       type=int, default=8000)
    p.add_argument("--host",       type=str, default="0.0.0.0")
    p.add_argument("--verbose",    action="store_true")
    p.add_argument("--interface",  type=str, default=None)
    p.add_argument("--no-monitor", action="store_true")
    args = p.parse_args()

    if args.serve:
        run_server(args.port, args.host, args.interface, args.no_monitor)
    else:
        asyncio.run(run_cli(args.scenario, args.verbose, args.interface, args.no_monitor))


if __name__ == "__main__":
    main()