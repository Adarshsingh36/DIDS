"""
DIDS Web Server — The Security Operations Center Dashboard

THINK OF IT AS
──────────────
An online security command center where you view:
- Real-time attack alerts (similar to news ticker)
- Agent status (security guards online/offline)
- Network threat level (green/yellow/red)
- Scenario controls (run test attacks remotely)
- System state snapshots (instant status check)

ALL IN YOUR WEB BROWSER

HOW TO START
────────────
# Terminal 1: Start the DIDS system with web server
python -m dids.web.server --port 8000

# Terminal 2: Open browser
http://localhost:8000

ENDPOINTS (What you can ask the server to do)
──────────────────────────────────────────────
GET  /              → Open the dashboard (HTML page)
                      Shows real-time alerts, agents, threat level

GET  /ws            → WebSocket connection (live data stream)
                      Browser connects here to receive real-time updates
                      Same technology YouTube uses for live comments

GET  /api/state     → Current system state as JSON (snapshot)
                      Used by the dashboard to populate initial display
                      Also available as downloadable JSON

POST /api/run/{scenario}  → Trigger a test attack
                      Scenario: brute, scan, ddos, mixed, all
                      Example: POST /api/run/ddos → Starts DDoS simulation
                      Runs in background (doesn't block dashboard)

GET  /api/proxies   → Status of all backup coordinator servers
                      Shows which proxies are standby vs active
                      Used by dashboard to display failover status

ARCHITECTURE FLOW
─────────────────
┌──────────────────────────────────────────────────┐
│      Web Browser (Your Security Monitor)         │
│  - Opens http://localhost:8000                   │
│  - Displays HTML dashboard                       │
│  - Shows real-time charts and alerts             │
└──────────┬───────────────────────────────────────┘
           │
           │ WebSocket connection (two-way live stream)
           │ Browser sends: scenario commands
           │ Server sends: alerts, beliefs, trust updates
           ▼
┌──────────────────────────────────────────────────┐
│        FastAPI Web Server (This Module)          │
│  - Receives WebSocket connections (/ws)          │
│  - Responds to REST API calls (/api/state, etc.) │
│  - Manages the system orchestrator                │
│  - Delegates to DashboardTap for live updates    │
└──────────┬───────────────────────────────────────┘
           │
           │ Owns and manages
           │
           ▼
┌──────────────────────────────────────────────────┐
│    System Orchestrator & DashboardTap            │
│  - Orchestrator: Master control of all agents    │
│  - DashboardTap: Bridges internal bus to web    │
│  - Serializes internal messages to JSON         │
└──────────────────────────────────────────────────┘

EXAMPLE FLOW: User Clicks "Run DDoS Attack"
────────────────────────────────────────────
1. Browser sends: POST /api/run/ddos
2. Server receives, creates AttackSimulator
3. Simulator generates fake DDoS events
4. Events reach the agents → belief updates
5. Beliefs sent on message bus
6. DashboardTap intercepts beliefs
7. DashboardTap serializes to JSON
8. DashboardTap broadcasts to all WebSocket clients
9. Browser receives JSON in real-time
10. JavaScript updates charts/alerts instantly
"""

from __future__ import annotations
import asyncio
import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

logger = logging.getLogger(__name__)

# ── Module-level references (set in lifespan) ─────────────────────────────────
_orch = None
_tap  = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI startup and shutdown lifecycle hook.
    
    STARTUP (runs once when server starts)
    ──────────────────────────────────────
    1. Create system orchestrator (master control of all agents)
    2. Build entire DIDS system (agents, coordinators, global engine, etc.)
    3. Get the tap that will broadcast updates to web clients
    4. Wait 0.3 seconds for all agents to register on message bus
    5. Save references globally so endpoints can access them
    
    SHUTDOWN (runs once when server stops)
    ──────────────────────────────────────
    1. Gracefully shutdown entire orchestrator
    2. Close all agent connections
    3. Stop all monitoring threads
    
    This pattern ensures:
    - Entire DIDS system starts when web server starts
    - Only one orchestrator instance (shared by all endpoints)
    - Clean startup/shutdown (no resource leaks)
    """
    global _orch, _tap
    from dids.core.orchestrator import DIDSOrchestrator, default_config
    _orch = DIDSOrchestrator(default_config())
    await _orch.build_and_start()
    _tap = _orch.tap
    await asyncio.sleep(0.3)    # let agents register
    yield
    if _orch:
        await _orch.shutdown()


app = FastAPI(title="DIDS Dashboard", lifespan=lifespan)


# ── WebSocket endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """
    Live download stream of all system events to web browsers.
    
    WHAT IS A WEBSOCKET?
    ────────────────────
    A WebSocket is like a telephone call between browser and server:
    - Regular HTTP: You send a request, wait for response, then disconnect
    - WebSocket: You connect, stay connected, receive infinite stream of updates in real-time
    
    This endpoint establishes a WebSocket connection with the browser and starts
    streaming real-time messages (alerts, belief updates, trust events, heartbeats).
    
    FLOW
    ────
    1. Browser opens WebSocket: ws://localhost:8000/ws
    2. Endpoint accepts connection
    3. Get message queue from DashboardTap (receives copy of all bus messages)
    4. Infinite loop:
       - Wait for message from queue (0.5 second timeout)
       - Send message as JSON string to browser
       - If timeout, send "ping" keep-alive (verifies connection still works)
    5. If browser disconnects (WebSocketDisconnect exception), remove queue and exit
    
    MESSAGES STREAMED
    ─────────────────
    - belief_update: Agent/coordinator updated its threat assessment
    - alert: Confirmed attack detected
    - heartbeat: Component still alive
    - trust_event: Trust voting started
    - trust_vote: Component cast trust vote
    - failover: Backup server activated
    """
    await ws.accept()
    client_q = _tap.add_client() if _tap else None
    try:
        while True:
            if client_q:
                try:
                    msg = await asyncio.wait_for(client_q.get(), timeout=0.5)
                    await ws.send_text(msg)
                except asyncio.TimeoutError:
                    await ws.send_text('{"type":"ping"}')
            else:
                await asyncio.sleep(1.0)
                await ws.send_text('{"type":"ping"}')
    except WebSocketDisconnect:
        if _tap and client_q:
            _tap.remove_client(client_q)


# ── REST endpoints ────────────────────────────────────────────────────────────

@app.get("/api/state")
async def get_state():
    """
    Get a snapshot of the current system state (JSON).
    
    ENDPOINT USAGE
    ──────────────
    GET http://localhost:8000/api/state
    
    Response: JSON dictionary containing:
    {
      "agent_beliefs": {
        "agent_a1": {"beliefs": {...}, "dominant": "brute_force", ...},
        ...
      },
      "agent_trust": {
        "agent_a1": {"trust": 0.95, "status": "TRUSTED"},
        ...
      },
      "coord_beliefs": {...},
      "global_belief": {...},
      "recent_alerts": [...],
      "backup_status": {...},
      "heartbeats": {...},
      "connected_clients": 2
    }
    
    USE CASES
    ─────────
    - Initial dashboard load: Populate UI with current state
    - Periodic refresh: Poll API to update view
    - Status check: Verify system is healthy
    - Debugging: Download JSON for inspection
    - External integration: Feed state to other tools
    """
    if _tap:
        return JSONResponse(_tap.get_state_snapshot())
    return JSONResponse({"error": "tap not initialised"})


@app.post("/api/run/{scenario}")
async def run_scenario(scenario: str):
    """
    Trigger a test attack scenario (simulate security threat).
    
    ENDPOINT USAGE
    ──────────────
    POST http://localhost:8000/api/run/ddos
    → Starts a DDoS simulation
    
    Response: {"status": "started", "scenario": "ddos"}
    
    AVAILABLE SCENARIOS
    ───────────────────
    - brute  → Brute force login attack on one agent
    - scan   → Port scanning attack on 4 agents
    - ddos   → DDoS flooding attack on all agents
    - mixed  → Multi-stage APT (recon → exploit → exfiltration)
    - all    → Run all scenarios sequentially with delays
    
    IMPORTANT
    ─────────
    ✓ Runs in background (returns immediately, doesn't wait for completion)
    ✓ Dashboard receives real-time updates as attack progresses
    ✓ Browser shows threat level increasing and alerts appearing
    ✓ Perfect for testing and demonstrations
    ✓ No real attackers involved (completely safe)
    
    ERROR RESPONSES
    ───────────────
    400 Bad Request: Unknown scenario (check spelling)
    503 Service Unavailable: Orchestrator not ready (system still starting)
    """
    valid = {"brute", "scan", "ddos", "mixed", "all"}
    if scenario not in valid:
        return JSONResponse({"error": f"unknown scenario '{scenario}'"}, status_code=400)
    if not _orch:
        return JSONResponse({"error": "orchestrator not ready"}, status_code=503)

    from dids.simulation.attack_simulator import AttackSimulator
    sim = AttackSimulator(list(_orch.agents.values()))
    agent_ids = _orch.agent_ids()

    async def _run():
        if scenario == "brute":
            await sim.brute_force_local(agent_ids[0])
        elif scenario == "scan":
            await sim.port_scan_sweep(agent_ids[:4])
        elif scenario == "ddos":
            await sim.ddos_distributed()
        elif scenario == "mixed":
            await sim.mixed_attack(agent_ids[0], agent_ids[-1])
        elif scenario == "all":
            await sim.run_all_scenarios()

    asyncio.create_task(_run())
    return JSONResponse({"status": "started", "scenario": scenario})


@app.get("/api/proxies")
async def get_proxies():
    """
    Get status of all backup coordinator servers (failover status).
    
    ENDPOINT USAGE
    ──────────────
    GET http://localhost:8000/api/proxies
    
    Response: JSON dictionary:
    {
      "proxies": [
        {
          "primary_id": "coord_a",
          "backup_id": "backup_coord_a",
          "status": "STANDBY",  or "ACTIVE",
          "reason": "Primary healthy"
        },
        ...
      ]
    }
    
    WHAT ARE PROXIES?
    ─────────────────
    Think of them like understudy actors in a theater:
    - Primary: Main coordinator processing agent reports (actively working)
    - Backup (Proxy): Watching and ready to take over (standby mode)
    
    When primary fails:
    - Backup automatically activates (switchover)
    - Takes over processing agent reports
    - Becomes ACTIVE until primary recovers
    
    USE CASES
    ─────────
    - Monitor failover health
    - Verify hot-standby setup is working
    - Dashboard displays proxy server configurations
    - Alert if backup not available (risky configuration)
    """
    if _orch:
        return JSONResponse({"proxies": _orch.get_proxy_status()})
    return JSONResponse({"proxies": []})


# ── HTML Dashboard ────────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DIDS — Security Operations Center</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
:root{--bg:#f5f8fb;--card:#ffffff;--card2:#eef4fb;--border:#d8e3ed;--text:#102a43;--muted:#64748b;--blue:#3b82f6;--green:#22c55e;--yellow:#fbbf24;--red:#ef4444;--purple:#8b5cf6;--cyan:#38bdf8;--orange:#fb923c}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:'Courier New',monospace;font-size:13px;overflow-x:hidden}
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}

/* ── Header ── */
.hdr{background:var(--card);border-bottom:1px solid var(--border);padding:10px 20px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.hdr-title{font-size:17px;font-weight:700;letter-spacing:3px;color:var(--cyan)}
.hdr-right{display:flex;align-items:center;gap:16px;font-size:12px;color:var(--muted)}
.ws-dot{width:8px;height:8px;border-radius:50%;background:var(--red);display:inline-block;margin-right:4px;transition:background .3s}
.ws-dot.ok{background:var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}

/* ── Scenario bar ── */
.scenario-bar{background:var(--card2);border-bottom:1px solid var(--border);padding:8px 20px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.scenario-bar span{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-right:4px}
.scn-btn{padding:5px 14px;border:1px solid var(--border);border-radius:5px;background:transparent;color:var(--text);cursor:pointer;font-size:12px;font-family:inherit;transition:all .15s}
.scn-btn:hover{background:var(--border);border-color:var(--cyan)}
.scn-btn.running{border-color:var(--green);color:var(--green);animation:pulse 1s infinite}

/* ── KPI row ── */
.kpi-row{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;padding:14px 20px}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 14px}
.kpi-lbl{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:5px}
.kpi-val{font-size:26px;font-weight:700;line-height:1}
.kpi-sub{font-size:10px;color:var(--muted);margin-top:4px}

/* ── Tabs ── */
.tab-bar{display:flex;gap:0;padding:0 20px;border-bottom:1px solid var(--border);background:var(--card)}
.tab{padding:9px 18px;cursor:pointer;font-size:12px;color:var(--muted);border-bottom:2px solid transparent;transition:all .15s;font-family:inherit;background:none;border-top:none;border-left:none;border-right:none}
.tab.active{color:var(--cyan);border-bottom-color:var(--cyan)}
.tab:hover{color:var(--text)}
.tab-content{display:none;padding:16px 20px}
.tab-content.active{display:block}

/* ── Cards ── */
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px}
.card-title{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.grid-auto{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px}

/* ── Agent tiles ── */
.agent-tile{background:var(--card2);border:1px solid var(--border);border-radius:7px;padding:10px;cursor:pointer;transition:border-color .2s}
.agent-tile:hover{border-color:var(--cyan)}
.agent-tile.selected{border-color:var(--cyan)}
.agent-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.agent-id{font-weight:700;font-size:13px}
.status-pill{font-size:9px;font-weight:700;padding:2px 6px;border-radius:10px;text-transform:uppercase}
.trusted{background:rgba(16,185,129,.15);color:var(--green);border:1px solid rgba(16,185,129,.3)}
.suspect{background:rgba(245,158,11,.15);color:var(--yellow);border:1px solid rgba(245,158,11,.3)}
.isolated{background:rgba(239,68,68,.15);color:var(--red);border:1px solid rgba(239,68,68,.3);animation:pulse 1s infinite}
.offline{background:rgba(148,163,184,.1);color:var(--muted);border:1px solid var(--border)}

/* ── Progress bars ── */
.bar-wrap{height:6px;background:var(--bg);border-radius:3px;overflow:hidden;margin:3px 0}
.bar-fill{height:100%;border-radius:3px;transition:width .5s ease}
.bar-label{display:flex;justify-content:space-between;font-size:10px;color:var(--muted)}

/* ── Alert feed ── */
.alert-item{display:flex;align-items:center;gap:8px;padding:6px 8px;border-radius:5px;margin-bottom:4px;font-size:12px;border-left:3px solid var(--border)}
.alert-item.CRITICAL{background:rgba(239,68,68,.08);border-left-color:var(--red)}
.alert-item.HIGH{background:rgba(249,115,22,.08);border-left-color:var(--orange)}
.alert-item.MEDIUM{background:rgba(245,158,11,.08);border-left-color:var(--yellow)}
.alert-item.LOW{background:rgba(59,130,246,.08);border-left-color:var(--blue)}
.alert-badge{font-size:9px;font-weight:700;padding:2px 5px;border-radius:3px;text-transform:uppercase;flex-shrink:0}
.badge-CRITICAL{background:rgba(239,68,68,.2);color:var(--red)}
.badge-HIGH{background:rgba(249,115,22,.2);color:var(--orange)}
.badge-MEDIUM{background:rgba(245,158,11,.2);color:var(--yellow)}
.badge-LOW{background:rgba(59,130,246,.2);color:var(--blue)}

/* ── Topology ── */
.topo-wrap{overflow:auto;min-height:320px;display:flex;justify-content:center;align-items:flex-start;padding:10px}
.topo-node{stroke:var(--border);stroke-width:1;rx:6}
.topo-text{font-family:'Courier New',monospace;font-size:11px;fill:var(--text);text-anchor:middle}
.topo-sub{font-family:'Courier New',monospace;font-size:9px;fill:var(--muted);text-anchor:middle}
.topo-line{stroke:var(--border);stroke-width:1}
.topo-node-wrap{cursor:pointer}

/* ── Proxy status ── */
.proxy-card{background:var(--card2);border:1px solid var(--border);border-radius:7px;padding:12px}
.proxy-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.proxy-badge{font-size:10px;font-weight:700;padding:2px 7px;border-radius:10px}
.proxy-standby{background:rgba(59,130,246,.15);color:var(--blue);border:1px solid rgba(59,130,246,.3)}
.proxy-active{background:rgba(249,115,22,.15);color:var(--orange);border:1px solid rgba(249,115,22,.3);animation:pulse 1s infinite}

/* ── Detail panel ── */
#detail-panel{background:var(--card2);border-radius:8px;padding:14px}
.belief-row{margin-bottom:6px}

/* ── Log table ── */
.log-table{width:100%;border-collapse:collapse;font-size:12px}
.log-table th{text-align:left;padding:6px 10px;border-bottom:1px solid var(--border);color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:1px;font-weight:normal}
.log-table td{padding:6px 10px;border-bottom:1px solid rgba(51,65,85,.4)}
.log-table tr:hover td{background:var(--card2)}

/* ── Misc ── */
.section-sep{height:1px;background:var(--border);margin:14px 0}
.threat-indicator{font-size:22px;font-weight:700}
.conn-count{font-size:10px;color:var(--muted)}
</style>
</head>
<body>

<!-- ── Header ── -->
<div class="hdr">
  <div class="hdr-title">DIDS <span style="color:var(--muted);font-size:12px;font-weight:400;letter-spacing:1px">// SECURITY OPS CENTER</span></div>
  <div class="hdr-right">
    <span><span class="ws-dot" id="ws-dot"></span><span id="ws-status">Connecting…</span></span>
    <span id="uptime-display">Uptime: 0s</span>
    <span id="msg-count">0 messages</span>
  </div>
</div>

<!-- ── Scenario control ── -->
<div class="scenario-bar">
  <span>Simulate:</span>
  <button class="scn-btn" onclick="runScenario('brute')" id="btn-brute">Brute Force</button>
  <button class="scn-btn" onclick="runScenario('scan')"  id="btn-scan">Port Scan</button>
  <button class="scn-btn" onclick="runScenario('ddos')"  id="btn-ddos">DDoS</button>
  <button class="scn-btn" onclick="runScenario('mixed')" id="btn-mixed">APT / Mixed</button>
  <button class="scn-btn" onclick="runScenario('all')"   id="btn-all">Run All</button>
  <span style="margin-left:auto;font-size:11px;color:var(--muted)" id="scenario-status"></span>
</div>

<!-- ── KPI row ── -->
<div class="kpi-row">
  <div class="kpi">
    <div class="kpi-lbl">Global Threat</div>
    <div class="kpi-val threat-indicator" id="kpi-threat" style="color:var(--green)">CLEAR</div>
    <div class="kpi-sub" id="kpi-threat-sub">—</div>
  </div>
  <div class="kpi">
    <div class="kpi-lbl">Critical Alerts</div>
    <div class="kpi-val" id="kpi-crit" style="color:var(--red)">0</div>
    <div class="kpi-sub" id="kpi-crit-sub">0 high</div>
  </div>
  <div class="kpi">
    <div class="kpi-lbl">Active Agents</div>
    <div class="kpi-val" id="kpi-agents" style="color:var(--green)">0 / 9</div>
    <div class="kpi-sub" id="kpi-agents-sub">0 isolated</div>
  </div>
  <div class="kpi">
    <div class="kpi-lbl">Dominant Attack</div>
    <div class="kpi-val" id="kpi-dom" style="font-size:14px;padding-top:6px">—</div>
    <div class="kpi-sub" id="kpi-dom-sub">p = 0.00</div>
  </div>
  <div class="kpi">
    <div class="kpi-lbl">Proxy Servers</div>
    <div class="kpi-val" id="kpi-proxy" style="color:var(--blue)">3</div>
    <div class="kpi-sub" id="kpi-proxy-sub">all standby</div>
  </div>
</div>

<!-- ── Tabs ── -->
<div class="tab-bar">
  <button class="tab active" onclick="switchTab('overview',this)">Overview</button>
  <button class="tab" onclick="switchTab('agents',this)">Agents</button>
  <button class="tab" onclick="switchTab('alerts',this)">Alerts</button>
  <button class="tab" onclick="switchTab('proxies',this)">Proxy Servers</button>
  <button class="tab" onclick="switchTab('topology',this)">Topology</button>
</div>

<!-- ═══════════════════ TAB: OVERVIEW ═══════════════════ -->
<div id="tab-overview" class="tab-content active">
  <div class="grid2">
    <div>
      <div class="card" style="margin-bottom:14px">
        <div class="card-title">Global Belief Over Time</div>
        <div style="position:relative;height:160px"><canvas id="history-chart"></canvas></div>
        <div id="history-legend" style="display:flex;flex-wrap:wrap;gap:10px;margin-top:8px"></div>
      </div>
      <div class="card">
        <div class="card-title">Attack Distribution</div>
        <div style="position:relative;height:150px"><canvas id="bar-chart"></canvas></div>
      </div>
    </div>
    <div>
      <div class="card" style="margin-bottom:14px;height:200px;overflow-y:auto">
        <div class="card-title">Live Alert Feed</div>
        <div id="live-feed"></div>
      </div>
      <div class="card">
        <div class="card-title">Trust Scores</div>
        <div id="trust-bars"></div>
      </div>
    </div>
  </div>
</div>

<!-- ═══════════════════ TAB: AGENTS ═══════════════════ -->
<div id="tab-agents" class="tab-content">
  <div class="grid2">
    <div>
      <div class="card">
        <div class="card-title">Agent Grid — click to inspect</div>
        <div class="grid3" id="agent-grid" style="margin-bottom:10px"></div>
        <div class="section-sep"></div>
        <div class="card-title" style="margin-top:10px">Subdomain Summary</div>
        <div class="grid3" id="subdomain-grid"></div>
      </div>
    </div>
    <div>
      <div class="card">
        <div class="card-title" id="detail-title">Select an agent</div>
        <div id="detail-panel">
          <div style="color:var(--muted);text-align:center;padding:40px 0">Click any agent to see detail</div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ═══════════════════ TAB: ALERTS ═══════════════════ -->
<div id="tab-alerts" class="tab-content">
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <div class="card-title" style="margin:0">Full Alert Log</div>
      <span id="alert-counts" style="font-size:11px;color:var(--muted)"></span>
    </div>
    <div style="overflow-x:auto;max-height:500px;overflow-y:auto">
      <table class="log-table">
        <thead><tr>
          <th>Time</th><th>Source</th><th>Attack</th><th>Confidence</th><th>Severity</th><th>IPs</th>
        </tr></thead>
        <tbody id="alert-log-body"></tbody>
      </table>
      <div id="alert-log-empty" style="text-align:center;padding:40px;color:var(--muted)">No alerts yet — run a scenario</div>
    </div>
  </div>
</div>

<!-- ═══════════════════ TAB: PROXY SERVERS ═══════════════════ -->
<div id="tab-proxies" class="tab-content">
  <div class="card" style="margin-bottom:14px">
    <div class="card-title">Proxy / Backup Coordinator Architecture</div>
    <div style="color:var(--muted);font-size:12px;line-height:1.8;margin-bottom:12px">
      Each subdomain coordinator has a hot-standby backup (proxy) that mirrors its state every 3 seconds.
      The HealthMonitor checks heartbeats every 2 seconds — if a primary misses 12s of heartbeats
      or its queue exceeds 80% capacity, the backup automatically activates and agents are redirected.
    </div>
    <div class="grid3" id="proxy-cards"></div>
  </div>
  <div class="card">
    <div class="card-title">Failover Event Log</div>
    <div id="failover-log" style="max-height:200px;overflow-y:auto;font-size:12px;color:var(--muted)">
      No failover events recorded.
    </div>
  </div>
</div>

<!-- ═══════════════════ TAB: TOPOLOGY ═══════════════════ -->
<div id="tab-topology" class="tab-content">
  <div class="card">
    <div class="card-title">Live System Topology</div>
    <div class="topo-wrap">
      <svg id="topology-svg" width="820" height="420" viewBox="0 0 820 420">
        <!-- Lines -->
        <line x1="410" y1="55" x2="410" y2="85" class="topo-line"/>
        <line x1="410" y1="130" x2="410" y2="160" class="topo-line"/>
        <line x1="410" y1="205" x2="410" y2="235" class="topo-line"/>
        <!-- Coordinator branches -->
        <line x1="410" y1="270" x2="180" y2="290" class="topo-line"/>
        <line x1="410" y1="270" x2="410" y2="290" class="topo-line"/>
        <line x1="410" y1="270" x2="640" y2="290" class="topo-line"/>
        <!-- Agent lines G0 -->
        <line x1="100" y1="330" x2="100" y2="355" class="topo-line"/>
        <line x1="180" y1="330" x2="180" y2="355" class="topo-line"/>
        <line x1="260" y1="330" x2="260" y2="355" class="topo-line"/>
        <!-- Agent lines G1 -->
        <line x1="330" y1="330" x2="330" y2="355" class="topo-line"/>
        <line x1="410" y1="330" x2="410" y2="355" class="topo-line"/>
        <line x1="490" y1="330" x2="490" y2="355" class="topo-line"/>
        <!-- Agent lines G2 -->
        <line x1="560" y1="330" x2="560" y2="355" class="topo-line"/>
        <line x1="640" y1="330" x2="640" y2="355" class="topo-line"/>
        <line x1="720" y1="330" x2="720" y2="355" class="topo-line"/>

        <!-- Dashboard -->
        <g id="topo-dashboard" class="topo-node-wrap">
          <rect x="310" y="10" width="200" height="45" rx="7" fill="#1e3a4a" stroke="#06b6d4" stroke-width="1.5" class="topo-node"/>
          <text x="410" y="30" class="topo-text" fill="#06b6d4" font-weight="700">Admin Dashboard</text>
          <text x="410" y="46" class="topo-sub">alert sink</text>
        </g>

        <!-- Global Engine -->
        <g id="topo-global" class="topo-node-wrap">
          <rect x="290" y="85" width="240" height="45" rx="7" fill="#1e2a4a" stroke="#8b5cf6" stroke-width="1.5"/>
          <text x="410" y="105" class="topo-text" fill="#8b5cf6" font-weight="700">Global Inference Engine</text>
          <text id="topo-global-sub" x="410" y="121" class="topo-sub">p=0.00 — CLEAR</text>
        </g>

        <!-- Trust Manager -->
        <g id="topo-dtm" class="topo-node-wrap">
          <rect x="290" y="160" width="240" height="45" rx="7" fill="#2a1e2a" stroke="#ec4899" stroke-width="1.5"/>
          <text x="410" y="180" class="topo-text" fill="#ec4899" font-weight="700">Trust Manager</text>
          <text id="topo-dtm-sub" x="410" y="196" class="topo-sub">Byzantine consensus</text>
        </g>

        <!-- Coordinators -->
        <g id="topo-coord-g0" class="topo-node-wrap" onclick="selectTopoNode('coord_g0')">
          <rect x="60" y="290" width="200" height="40" rx="6" fill="#1a2a1a" stroke="#10b981" stroke-width="1.5"/>
          <text x="160" y="308" class="topo-text" fill="#10b981" font-weight="700">Coordinator G0</text>
          <text id="topo-g0-sub" x="160" y="323" class="topo-sub">subdomain A</text>
        </g>
        <g id="topo-coord-g1" class="topo-node-wrap" onclick="selectTopoNode('coord_g1')">
          <rect x="290" y="290" width="200" height="40" rx="6" fill="#1a2a1a" stroke="#10b981" stroke-width="1.5"/>
          <text x="390" y="308" class="topo-text" fill="#10b981" font-weight="700">Coordinator G1</text>
          <text id="topo-g1-sub" x="390" y="323" class="topo-sub">subdomain B</text>
        </g>
        <g id="topo-coord-g2" class="topo-node-wrap" onclick="selectTopoNode('coord_g2')">
          <rect x="520" y="290" width="200" height="40" rx="6" fill="#1a2a1a" stroke="#10b981" stroke-width="1.5"/>
          <text x="620" y="308" class="topo-text" fill="#10b981" font-weight="700">Coordinator G2</text>
          <text id="topo-g2-sub" x="620" y="323" class="topo-sub">subdomain C</text>
        </g>

        <!-- Agents row -->
        <g id="topo-agents">
          <rect id="ta-a1" x="62" y="355" width="75" height="35" rx="5" fill="#1e293b" stroke="#334155"/>
          <text x="100" y="370" class="topo-text">A1</text>
          <text id="ts-a1" x="100" y="382" class="topo-sub">100%</text>

          <rect id="ta-a2" x="142" y="355" width="75" height="35" rx="5" fill="#1e293b" stroke="#334155"/>
          <text x="180" y="370" class="topo-text">A2</text>
          <text id="ts-a2" x="180" y="382" class="topo-sub">100%</text>

          <rect id="ta-a3" x="222" y="355" width="75" height="35" rx="5" fill="#1e293b" stroke="#334155"/>
          <text x="260" y="370" class="topo-text">A3</text>
          <text id="ts-a3" x="260" y="382" class="topo-sub">100%</text>

          <rect id="ta-b1" x="292" y="355" width="75" height="35" rx="5" fill="#1e293b" stroke="#334155"/>
          <text x="330" y="370" class="topo-text">B1</text>
          <text id="ts-b1" x="330" y="382" class="topo-sub">100%</text>

          <rect id="ta-b2" x="372" y="355" width="75" height="35" rx="5" fill="#1e293b" stroke="#334155"/>
          <text x="410" y="370" class="topo-text">B2</text>
          <text id="ts-b2" x="410" y="382" class="topo-sub">100%</text>

          <rect id="ta-b3" x="452" y="355" width="75" height="35" rx="5" fill="#1e293b" stroke="#334155"/>
          <text x="490" y="370" class="topo-text">B3</text>
          <text id="ts-b3" x="490" y="382" class="topo-sub">100%</text>

          <rect id="ta-c1" x="522" y="355" width="75" height="35" rx="5" fill="#1e293b" stroke="#334155"/>
          <text x="560" y="370" class="topo-text">C1</text>
          <text id="ts-c1" x="560" y="382" class="topo-sub">100%</text>

          <rect id="ta-c2" x="602" y="355" width="75" height="35" rx="5" fill="#1e293b" stroke="#334155"/>
          <text x="640" y="370" class="topo-text">C2</text>
          <text id="ts-c2" x="640" y="382" class="topo-sub">100%</text>

          <rect id="ta-c3" x="682" y="355" width="75" height="35" rx="5" fill="#1e293b" stroke="#334155"/>
          <text x="720" y="370" class="topo-text">C3</text>
          <text id="ts-c3" x="720" y="382" class="topo-sub">100%</text>
        </g>
      </svg>
    </div>
  </div>
</div>

<script>
// ══════════════════════════════════════════════════════════════════════════════
// State
// ══════════════════════════════════════════════════════════════════════════════
const AGENTS = ['agent_a1','agent_a2','agent_a3','agent_b1','agent_b2','agent_b3','agent_c1','agent_c2','agent_c3'];
const SUBS = {G0:['agent_a1','agent_a2','agent_a3'],G1:['agent_b1','agent_b2','agent_b3'],G2:['agent_c1','agent_c2','agent_c3']};
const ATTACKS = ['brute_force','port_scan','ddos','privilege_escalation','data_exfiltration','malware'];
const A_LABELS = {brute_force:'Brute Force',port_scan:'Port Scan',ddos:'DDoS',privilege_escalation:'Priv. Escal.',data_exfiltration:'Data Exfil',malware:'Malware'};
const A_COLORS = {brute_force:'#ef4444',port_scan:'#8b5cf6',ddos:'#f97316',privilege_escalation:'#eab308',data_exfiltration:'#3b82f6',malware:'#ec4899'};
const STATUS_COLORS = {TRUSTED:'#10b981',SUSPECT:'#f59e0b',ISOLATED:'#ef4444',OFFLINE:'#64748b'};

let state = {
  beliefs: Object.fromEntries(AGENTS.map(id=>[id,{}])),
  trust:   Object.fromEntries(AGENTS.map(id=>[id,{trust:1.0,status:'TRUSTED'}])),
  coords:  {coord_g0:{},coord_g1:{},coord_g2:{}},
  global:  null,
  alerts:  [],
  backups: {},
  failoverLog: [],
  selectedAgent: null,
  msgCount: 0,
  startTime: Date.now(),
};

// ══════════════════════════════════════════════════════════════════════════════
// WebSocket
// ══════════════════════════════════════════════════════════════════════════════
let ws = null;
function connect() {
  ws = new WebSocket(`ws://${location.host}/ws`);
  ws.onopen = () => {
    document.getElementById('ws-dot').className = 'ws-dot ok';
    document.getElementById('ws-status').textContent = 'Connected';
  };
  ws.onclose = () => {
    document.getElementById('ws-dot').className = 'ws-dot';
    document.getElementById('ws-status').textContent = 'Reconnecting…';
    setTimeout(connect, 2000);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = (e) => {
    state.msgCount++;
    const msg = JSON.parse(e.data);
    handleMessage(msg);
  };
}

function handleMessage(msg) {
  switch(msg.type) {
    case 'snapshot':
      if(msg.agent_beliefs) Object.assign(state.beliefs, msg.agent_beliefs);
      if(msg.agent_trust)   Object.assign(state.trust, msg.agent_trust);
      if(msg.coord_beliefs) Object.assign(state.coords, msg.coord_beliefs);
      if(msg.global_belief) state.global = msg.global_belief;
      if(msg.recent_alerts) state.alerts = [...msg.recent_alerts, ...state.alerts].slice(0,100);
      if(msg.backup_status) Object.assign(state.backups, msg.backup_status);
      break;
    case 'belief_update':
      if(msg.node_type === 'agent') state.beliefs[msg.sender] = msg;
      else if(msg.node_type === 'coordinator') state.coords[msg.sender] = msg;
      else if(msg.node_type === 'global') state.global = msg;
      break;
    case 'alert':
      state.alerts.unshift(msg);
      if(state.alerts.length > 100) state.alerts.pop();
      break;
    case 'trust_update':
      state.trust[msg.node_id] = {trust: msg.trust, status: msg.status};
      break;
    case 'backup_status':
      state.backups[msg.backup_id] = msg;
      break;
    case 'failover':
      state.failoverLog.unshift({...msg, ts: new Date().toLocaleTimeString()});
      break;
    case 'ping': return;
  }
  renderAll();
}

// ══════════════════════════════════════════════════════════════════════════════
// Scenario control
// ══════════════════════════════════════════════════════════════════════════════
function runScenario(sc) {
  const btn = document.getElementById('btn-'+sc);
  if(btn) { btn.classList.add('running'); setTimeout(()=>btn.classList.remove('running'), 5000); }
  document.getElementById('scenario-status').textContent = `Running: ${sc}…`;
  fetch(`/api/run/${sc}`, {method:'POST'})
    .then(r=>r.json())
    .then(()=>{ setTimeout(()=>document.getElementById('scenario-status').textContent='', 6000); });
}

// ══════════════════════════════════════════════════════════════════════════════
// Charts
// ══════════════════════════════════════════════════════════════════════════════
let histChart = null, barChart = null;
let historyData = [];

function initCharts() {
  // History line chart
  const hctx = document.getElementById('history-chart').getContext('2d');
  histChart = new Chart(hctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: ATTACKS.map(a => ({
        label: A_LABELS[a], data: [], borderColor: A_COLORS[a],
        borderWidth: 1.5, pointRadius: 0, tension: 0.4, fill: false
      }))
    },
    options: {
      responsive: true, maintainAspectRatio: false, animation: {duration:300},
      plugins: { legend: {display:false} },
      scales: {
        x: { display: false },
        y: { min:0, max:100, ticks:{font:{size:9},maxTicksLimit:5},
             grid:{color:'rgba(51,65,85,.5)'} }
      }
    }
  });

  // History legend
  const leg = document.getElementById('history-legend');
  leg.innerHTML = ATTACKS.map(a =>
    `<span style="display:flex;align-items:center;gap:4px;font-size:10px;color:#94a3b8">
      <span style="width:10px;height:3px;background:${A_COLORS[a]};display:inline-block;border-radius:2px"></span>
      ${A_LABELS[a]}
    </span>`
  ).join('');

  // Bar chart
  const bctx = document.getElementById('bar-chart').getContext('2d');
  barChart = new Chart(bctx, {
    type: 'bar',
    data: {
      labels: ATTACKS.map(a=>A_LABELS[a]),
      datasets: [{
        data: ATTACKS.map(()=>Math.round(100/6)),
        backgroundColor: ATTACKS.map(a=>A_COLORS[a]),
        borderRadius: 3,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, indexAxis:'y',
      animation: {duration:400},
      plugins: {legend:{display:false}},
      scales: {
        x: {min:0,max:100,ticks:{font:{size:9}},grid:{color:'rgba(51,65,85,.5)'}},
        y: {ticks:{font:{size:9},color:'#94a3b8'}}
      }
    }
  });
}

function updateCharts() {
  if(!histChart || !barChart) return;
  const gb = state.global;
  if(!gb || !gb.beliefs) return;

  const vals = ATTACKS.map(a=>Math.round((gb.beliefs[a]||0)*100));
  barChart.data.datasets[0].data = vals;
  barChart.update('none');

  historyData.push(vals);
  if(historyData.length > 60) historyData.shift();
  histChart.data.labels = historyData.map((_,i)=>i);
  ATTACKS.forEach((a,i) => {
    histChart.data.datasets[i].data = historyData.map(h=>h[i]);
  });
  histChart.update('none');
}

// ══════════════════════════════════════════════════════════════════════════════
// Render functions
// ══════════════════════════════════════════════════════════════════════════════
function threatColor(level) {
  return {CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#f59e0b',LOW:'#3b82f6',CLEAR:'#10b981'}[level]||'#94a3b8';
}

function renderKPIs() {
  const gb = state.global;
  const level = gb ? gb.threat_level : 'CLEAR';
  const dom   = gb ? gb.dominant : '—';
  const maxP  = gb ? gb.max_p : 0;

  const kt = document.getElementById('kpi-threat');
  kt.textContent = level;
  kt.style.color = threatColor(level);
  document.getElementById('kpi-threat-sub').textContent = dom !== 'unknown' ? dom : '—';

  const crits = state.alerts.filter(a=>a.level==='CRITICAL').length;
  const highs  = state.alerts.filter(a=>a.level==='HIGH').length;
  document.getElementById('kpi-crit').textContent = crits;
  document.getElementById('kpi-crit-sub').textContent = `${highs} high`;

  const isolated = Object.values(state.trust).filter(t=>t.status==='ISOLATED').length;
  const suspects = Object.values(state.trust).filter(t=>t.status==='SUSPECT').length;
  document.getElementById('kpi-agents').textContent = `${9-isolated} / 9`;
  document.getElementById('kpi-agents').style.color = isolated>0?'#f59e0b':'#10b981';
  document.getElementById('kpi-agents-sub').textContent = `${isolated} isolated, ${suspects} suspect`;

  document.getElementById('kpi-dom').textContent = dom!=='unknown'?A_LABELS[dom]||dom:'—';
  document.getElementById('kpi-dom').style.color = dom!=='unknown'?(A_COLORS[dom]||'#e2e8f0'):'#94a3b8';
  document.getElementById('kpi-dom-sub').textContent = `p = ${maxP.toFixed(2)}`;

  const activeProxies = Object.values(state.backups).filter(b=>b.active).length;
  document.getElementById('kpi-proxy').textContent = Object.keys(state.backups).length || 3;
  document.getElementById('kpi-proxy-sub').textContent = activeProxies>0?`${activeProxies} ACTIVE`:'all standby';
  document.getElementById('kpi-proxy').style.color = activeProxies>0?'#f97316':'#3b82f6';
}

function renderAlertFeed() {
  const feed = document.getElementById('live-feed');
  if(!state.alerts.length) {
    feed.innerHTML = '<div style="color:#64748b;text-align:center;padding:20px 0;font-size:12px">No alerts yet</div>';
    return;
  }
  feed.innerHTML = state.alerts.slice(0,15).map(a=>`
    <div class="alert-item ${a.level}">
      <span class="alert-badge badge-${a.level}">${a.level}</span>
      <span style="color:${A_COLORS[a.attack]||'#e2e8f0'};flex:1">${A_LABELS[a.attack]||a.attack}</span>
      <span style="color:#64748b">${(a.source_node||'').replace('agent_','').toUpperCase()}</span>
      <span style="color:#64748b">${Math.round(a.probability*100)}%</span>
    </div>
  `).join('');
}

function renderTrustBars() {
  const el = document.getElementById('trust-bars');
  el.innerHTML = AGENTS.map(id => {
    const t = state.trust[id] || {trust:1.0,status:'TRUSTED'};
    const pct = Math.round(t.trust*100);
    const color = STATUS_COLORS[t.status]||'#64748b';
    const shortId = id.replace('agent_','').toUpperCase();
    return `<div style="margin-bottom:6px">
      <div class="bar-label"><span>${shortId}</span><span style="color:${color}">${t.status} ${pct}%</span></div>
      <div class="bar-wrap"><div class="bar-fill" style="width:${pct}%;background:${color}"></div></div>
    </div>`;
  }).join('');
}

function renderAgentGrid() {
  const grid = document.getElementById('agent-grid');
  grid.innerHTML = AGENTS.map(id => {
    const b = state.beliefs[id] || {};
    const t = state.trust[id] || {trust:1.0,status:'TRUSTED'};
    const dom = b.dominant || 'unknown';
    const maxP = b.max_p || 0;
    const sc = t.status.toLowerCase();
    const color = STATUS_COLORS[t.status]||'#64748b';
    const sel = state.selectedAgent===id ? ' selected' : '';
    return `<div class="agent-tile${sel}" onclick="selectAgent('${id}')">
      <div class="agent-hdr">
        <span class="agent-id">${id.replace('agent_','').toUpperCase()}</span>
        <span class="status-pill ${sc}">${t.status}</span>
      </div>
      <div class="bar-label"><span style="color:#64748b;font-size:10px">Trust</span><span style="font-size:10px;color:${color}">${Math.round(t.trust*100)}%</span></div>
      <div class="bar-wrap"><div class="bar-fill" style="width:${Math.round(t.trust*100)}%;background:${color}"></div></div>
      ${maxP>0.25?`<div style="font-size:10px;margin-top:5px;color:${A_COLORS[dom]||'#94a3b8'}">${A_LABELS[dom]||dom} ${Math.round(maxP*100)}%</div>`:''}
    </div>`;
  }).join('');

  // Subdomain summary
  const sg = document.getElementById('subdomain-grid');
  sg.innerHTML = Object.entries(SUBS).map(([sdName, agentList]) => {
    const cb = state.coords[`coord_g${sdName[1].toLowerCase()}`] || {};
    const dom = cb.dominant||'unknown'; const maxP = cb.max_p||0;
    return `<div style="background:var(--card2);border:1px solid var(--border);border-radius:6px;padding:8px">
      <div style="font-weight:700;color:#10b981;margin-bottom:4px">Subdomain ${sdName}</div>
      <div style="font-size:10px;color:#64748b">${agentList.map(id=>id.replace('agent_','').toUpperCase()).join(', ')}</div>
      ${maxP>0.2?`<div style="font-size:10px;margin-top:4px;color:${A_COLORS[dom]||'#94a3b8'}">${A_LABELS[dom]||dom} ${Math.round(maxP*100)}%</div>`:''}
    </div>`;
  }).join('');
}

function selectAgent(id) {
  state.selectedAgent = id;
  document.getElementById('detail-title').textContent = `Agent — ${id.replace('agent_','').toUpperCase()}`;
  const b = state.beliefs[id] || {};
  const t = state.trust[id] || {trust:1.0,status:'TRUSTED'};
  const color = STATUS_COLORS[t.status]||'#64748b';
  const beliefs = b.beliefs || {};
  const sorted = ATTACKS.map(a=>({a,v:beliefs[a]||0})).sort((x,y)=>y.v-x.v);

  document.getElementById('detail-panel').innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
      <span class="status-pill ${t.status.toLowerCase()}">${t.status}</span>
      <span style="font-size:12px;color:#94a3b8">${id}</span>
    </div>
    <div style="margin-bottom:14px">
      <div class="bar-label"><span style="color:#94a3b8">Trust Score</span><span style="color:${color}">${Math.round(t.trust*100)}%</span></div>
      <div class="bar-wrap" style="height:8px"><div class="bar-fill" style="width:${Math.round(t.trust*100)}%;background:${color}"></div></div>
    </div>
    <div style="font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Belief Distribution</div>
    ${sorted.map(({a,v})=>`
      <div class="belief-row">
        <div class="bar-label">
          <span style="color:${A_COLORS[a]}">${A_LABELS[a]}</span>
          <span style="color:#64748b">${Math.round(v*100)}%</span>
        </div>
        <div class="bar-wrap"><div class="bar-fill" style="width:${Math.round(v*100)}%;background:${A_COLORS[a]}"></div></div>
      </div>
    `).join('')}
  `;
  renderAgentGrid();
}

function renderAlertLog() {
  const body = document.getElementById('alert-log-body');
  const empty = document.getElementById('alert-log-empty');
  const counts = document.getElementById('alert-counts');
  if(!state.alerts.length) { body.innerHTML=''; empty.style.display='block'; counts.textContent=''; return; }
  empty.style.display='none';
  const crits = state.alerts.filter(a=>a.level==='CRITICAL').length;
  counts.textContent = `${state.alerts.length} total · ${crits} critical`;
  body.innerHTML = state.alerts.map(a=>{
    const ts = new Date(a.timestamp*1000).toLocaleTimeString();
    return `<tr>
      <td style="color:#64748b">${ts}</td>
      <td style="font-weight:700">${(a.source_node||'').replace('agent_','').toUpperCase()}</td>
      <td style="color:${A_COLORS[a.attack]||'#e2e8f0'}">${A_LABELS[a.attack]||a.attack}</td>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          <div class="bar-wrap" style="width:80px"><div class="bar-fill" style="width:${Math.round(a.probability*100)}%;background:${A_COLORS[a.attack]||'#64748b'}"></div></div>
          <span style="color:#64748b">${Math.round(a.probability*100)}%</span>
        </div>
      </td>
      <td><span class="alert-badge badge-${a.level}">${a.level}</span></td>
      <td style="color:#64748b;font-size:11px">${(a.involved_ips||[]).slice(0,2).join(', ')}</td>
    </tr>`;
  }).join('');
}

function renderProxies() {
  const el = document.getElementById('proxy-cards');
  const backupIds = ['coord_g0_backup','coord_g1_backup','coord_g2_backup'];
  const primaries = ['coord_g0','coord_g1','coord_g2'];

  el.innerHTML = backupIds.map((bid,i)=>{
    const info = state.backups[bid] || {active:false,reason:'',primary_id:primaries[i]};
    const isActive = info.active;
    return `<div class="proxy-card">
      <div class="proxy-hdr">
        <div>
          <div style="font-weight:700;font-size:13px">${bid.replace('coord_','').replace('_backup',' Backup').toUpperCase()}</div>
          <div style="font-size:10px;color:#64748b;margin-top:2px">mirrors ${info.primary_id||primaries[i]}</div>
        </div>
        <span class="proxy-badge ${isActive?'proxy-active':'proxy-standby'}">${isActive?'ACTIVE':'STANDBY'}</span>
      </div>
      ${isActive?`<div style="font-size:11px;color:#f97316;margin-top:6px">Reason: ${info.reason||'primary failure'}</div>`:''}
      <div style="font-size:11px;color:#64748b;margin-top:6px">
        State sync every 3s · Heartbeat check every 2s
      </div>
    </div>`;
  }).join('');

  const failLog = document.getElementById('failover-log');
  if(!state.failoverLog.length) {
    failLog.innerHTML = '<div style="padding:10px">No failover events recorded.</div>';
  } else {
    failLog.innerHTML = state.failoverLog.map(e=>
      `<div style="padding:5px 0;border-bottom:1px solid var(--border)">[${e.ts}] ${e.old_node} → ${e.new_node} (${e.reason||''})</div>`
    ).join('');
  }
}

function renderTopology() {
  // Update agent nodes in topology SVG
  const agentMap = {a1:'agent_a1',a2:'agent_a2',a3:'agent_a3',b1:'agent_b1',b2:'agent_b2',b3:'agent_b3',c1:'agent_c1',c2:'agent_c2',c3:'agent_c3'};
  Object.entries(agentMap).forEach(([short, full]) => {
    const rect = document.getElementById(`ta-${short}`);
    const txt  = document.getElementById(`ts-${short}`);
    if(!rect || !txt) return;
    const t = state.trust[full]||{trust:1.0,status:'TRUSTED'};
    const color = STATUS_COLORS[t.status]||'#334155';
    rect.setAttribute('stroke', color);
    txt.textContent = `${Math.round(t.trust*100)}%`;
    txt.setAttribute('fill', color);
  });

  // Global engine sub-label
  const gb = state.global;
  if(gb) {
    const sub = document.getElementById('topo-global-sub');
    if(sub) sub.textContent = `p=${gb.max_p.toFixed(2)} — ${gb.threat_level}`;
  }

  // DTM sub-label
  const isolated = Object.values(state.trust).filter(t=>t.status==='ISOLATED').length;
  const suspect  = Object.values(state.trust).filter(t=>t.status==='SUSPECT').length;
  const dtmSub = document.getElementById('topo-dtm-sub');
  if(dtmSub) dtmSub.textContent = `${isolated} isolated · ${suspect} suspect`;

  // Coordinator sub-labels
  ['g0','g1','g2'].forEach(g=>{
    const cb = state.coords[`coord_${g}`]||{};
    const sub = document.getElementById(`topo-${g}-sub`);
    if(sub && cb.dominant && cb.max_p > 0.25)
      sub.textContent = `${A_LABELS[cb.dominant]||cb.dominant} ${Math.round(cb.max_p*100)}%`;
  });
}

function renderUptime() {
  const sec = Math.floor((Date.now()-state.startTime)/1000);
  const h = Math.floor(sec/3600), m = Math.floor((sec%3600)/60), s = sec%60;
  document.getElementById('uptime-display').textContent =
    `Uptime: ${h>0?h+'h ':''}${m>0?m+'m ':''}${s}s`;
  document.getElementById('msg-count').textContent = `${state.msgCount} msgs`;
}

function renderAll() {
  renderKPIs();
  renderAlertFeed();
  renderTrustBars();
  renderAgentGrid();
  renderAlertLog();
  renderProxies();
  renderTopology();
  updateCharts();
}

// ── Tab switching ─────────────────────────────────────────────────────────────
function switchTab(name, el) {
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById(`tab-${name}`).classList.add('active');
  el.classList.add('active');
}

function selectTopoNode(id) {
  state.selectedAgent = id;
  switchTab('agents', document.querySelectorAll('.tab')[1]);
  selectAgent(id);
}

// ── Boot ──────────────────────────────────────────────────────────────────────
window.addEventListener('load', () => {
  initCharts();
  renderAll();
  connect();
  setInterval(renderUptime, 1000);
  setInterval(renderAll, 3000);   // fallback re-render every 3s
  // Load initial state via REST
  fetch('/api/state').then(r=>r.json()).then(data=>{
    if(data.agent_beliefs)  Object.assign(state.beliefs, data.agent_beliefs);
    if(data.agent_trust)    Object.assign(state.trust, data.agent_trust);
    if(data.coord_beliefs)  Object.assign(state.coords, data.coord_beliefs);
    if(data.global_belief)  state.global = data.global_belief;
    if(data.recent_alerts)  state.alerts = data.recent_alerts;
    if(data.backup_status)  Object.assign(state.backups, data.backup_status);
    renderAll();
  }).catch(()=>{});
  // Load proxy status
  fetch('/api/proxies').then(r=>r.json()).then(data=>{
    if(data.proxies) data.proxies.forEach(p=>{
      state.backups[p.backup_id] = p;
    });
    renderAll();
  }).catch(()=>{});
});
</script>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """
    Serve the main security dashboard HTML page.
    
    When you open http://localhost:8000 in your browser:
    1. Browser requests GET /
    2. This endpoint returns DASHBOARD_HTML (large HTML string defined above)
    3. Browser renders the HTML page
    4. JavaScript in the page opens WebSocket connection to /ws
    5. Dashboard starts displaying real-time data
    
    The HTML includes:
    - CSS styling (security-themed dark/light blue design)
    - Charts.js library for real-time threat level graphs
    - JavaScript to:
      * Connect to WebSocket
      * Parse incoming JSON messages
      * Update charts, alerts, KPIs, agent status
      * Send scenario commands to /api/run/{scenario}
    
    This is a "Single Page Application" (SPA):
    - Load HTML once
    - All updates via WebSocket (no page reloads)
    - Results in smooth, responsive real-time dashboard
    """
    return HTMLResponse(DASHBOARD_HTML)


# ── CLI entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", type=str, default="0.0.0.0")
    args = parser.parse_args()
    uvicorn.run("dids.web.server:app", host=args.host,
                port=args.port, reload=False)
