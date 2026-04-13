#!/usr/bin/env python3
"""
DevPulse - 3-Minute Disaster Recovery Demo
============================================

This script demonstrates DevPulse's autonomous security capabilities:

1. DETECT  - Rogue AI agent sending suspicious API requests
2. ANALYZE - Real-time pattern matching against OWASP Top 10
3. BLOCK   - Kill switch automatically severs the API key
4. RECOVER - System restores safe state with audit trail

Run: python scripts/disaster_demo.py [--live]
"""

import sys
import os
import time
import json
import asyncio
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from services.kill_switch import KillSwitch
from services.risk_score_engine import RiskScoreEngine, SecurityFinding
from services.thinking_tokens import ThinkingTokenTracker

# ANSI colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    print(f"""
{RED}{BOLD}
 ____            ____        _
|  _ \\  _____   |  _ \\ _   _| |___  ___
| | | |/ _ \\ \\ / / |_) | | | | / __|/ _ \\
| |_| |  __/\\ V /|  __/| |_| | \\__ \\  __/
|____/ \\___| \\_/ |_|    \\__,_|_|___/\\___|

    DISASTER RECOVERY DEMO v1.0
{RESET}
{YELLOW}This demo simulates a rogue AI agent attacking your APIs
and shows how DevPulse autonomously detects, blocks, and recovers.{RESET}
""")


def pause(seconds=2.0):
    """Dramatic pause for demo effect"""
    time.sleep(seconds)


def step(num, title, color=CYAN):
    print(f"\n{color}{BOLD}{'='*60}")
    print(f"  STEP {num}: {title}")
    print(f"{'='*60}{RESET}\n")
    pause(1.5)


def simulate_log(msg, level="INFO"):
    ts = datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]
    colors = {"INFO": GREEN, "WARN": YELLOW, "ERROR": RED, "CRITICAL": RED + BOLD}
    color = colors.get(level, GREEN)
    print(f"  {color}[{ts}] [{level}] {msg}{RESET}")
    pause(0.3)


def run_demo(live_mode=False):
    print_banner()

    # ------------------------------------------------------------------ #
    # PHASE 1: Normal Operations
    # ------------------------------------------------------------------ #
    step(1, "NORMAL OPERATIONS - Baseline Monitoring", GREEN)
    print(f"  {GREEN}System is healthy. Processing legitimate API requests...{RESET}\n")

    kill_switch = KillSwitch()
    risk_engine = RiskScoreEngine()
    token_tracker = ThinkingTokenTracker()

    # Simulate normal requests
    normal_requests = [
        ("GET", "/api/users/profile", 200, 45),
        ("POST", "/api/collections/import", 201, 320),
        ("GET", "/api/risk-score", 200, 89),
        ("POST", "/api/scan/code", 200, 1250),
        ("GET", "/api/tokens/analytics", 200, 67),
    ]

    for method, endpoint, status_code, latency_ms in normal_requests:
        simulate_log(f"{method} {endpoint} -> {status_code} ({latency_ms}ms)")

    token_tracker.track_tokens("normal_001", "gpt-4", 500, 300, 0, "code_review")
    print(f"\n  {GREEN}All requests normal. Risk score: 0/100{RESET}")
    pause(2)

    # ------------------------------------------------------------------ #
    # PHASE 2: Rogue Agent Attack
    # ------------------------------------------------------------------ #
    step(2, "ATTACK DETECTED - Rogue AI Agent Activated", RED)
    print(f"  {RED}A compromised AI agent begins sending malicious requests...{RESET}\n")

    attack_requests = [
        ("POST", "/api/scan/code", "eval(request.body)", "CODE_EXECUTION"),
        ("GET", "/api/users?id=1' OR '1'='1", "SQL injection attempt", "SQL_INJECTION"),
        ("POST", "/api/collections/import", "../../etc/passwd", "PATH_TRAVERSAL"),
        ("GET", "/api/admin?token=stolen_admin_key", "Privilege escalation", "AUTH_BYPASS"),
        ("POST", "/api/webhooks/exec", "<script>fetch('evil.com')</script>", "XSS"),
    ]

    findings = []
    for method, endpoint, payload, attack_type in attack_requests:
        simulate_log(f"ATTACK: {method} {endpoint}", "WARN")
        simulate_log(f"  Payload: {payload[:50]}...", "WARN")
        simulate_log(f"  Pattern: {attack_type}", "WARN")

        finding = SecurityFinding(
            id=f"finding_{len(findings)}",
            title=f"{attack_type} detected on {endpoint}",
            severity="CRITICAL" if attack_type in ["SQL_INJECTION", "CODE_EXECUTION"] else "HIGH",
            category=attack_type,
            description=f"Malicious {attack_type} payload detected",
            remediation=f"Block and rotate API keys",
            affected_endpoints=[endpoint],
        )
        findings.append(finding)
        pause(0.5)

    # Infinite reasoning loop
    print(f"\n  {RED}{BOLD}INFINITE REASONING LOOP DETECTED!{RESET}")
    simulate_log("Agent requesting o1 with 50,000 thinking tokens per call", "CRITICAL")
    simulate_log("Token burn rate: $2.50/minute (10x normal)", "CRITICAL")
    simulate_log("Estimated monthly cost if unchecked: $108,000", "CRITICAL")

    token_tracker.track_tokens("rogue_001", "o1", 2000, 5000, 50000, "rogue_analysis")
    token_tracker.track_tokens("rogue_002", "o1", 3000, 8000, 75000, "rogue_analysis")
    pause(2)

    # ------------------------------------------------------------------ #
    # PHASE 3: Kill Switch Activation
    # ------------------------------------------------------------------ #
    step(3, "KILL SWITCH ACTIVATED - Autonomous Response", MAGENTA)

    risk_engine.add_findings(findings)
    metrics = risk_engine.get_metrics()
    print(f"  {RED}Risk Score: {metrics.risk_score}/100 ({metrics.risk_level}){RESET}")
    print(f"  {RED}Critical: {metrics.critical_count} | High: {metrics.high_count}{RESET}\n")
    pause(1)

    print(f"  {MAGENTA}{BOLD}ACTIVATING AUTONOMOUS KILL SWITCH...{RESET}\n")
    pause(1)

    # Block each attack
    for i, (method, endpoint, payload, attack_type) in enumerate(attack_requests):
        result = kill_switch.block_request(f"req_{i}", attack_type)
        simulate_log(f"BLOCKED: {attack_type} on {endpoint}", "CRITICAL")

    print(f"\n  {MAGENTA}{BOLD}API KEY SEVERED{RESET}")
    simulate_log("Rogue agent API key revoked: ak_rogue_***", "CRITICAL")
    simulate_log("All active sessions terminated", "CRITICAL")
    simulate_log("IP address 203.0.113.42 blocked", "CRITICAL")
    pause(2)

    # ------------------------------------------------------------------ #
    # PHASE 4: Recovery
    # ------------------------------------------------------------------ #
    step(4, "RECOVERY COMPLETE - System Restored", GREEN)

    print(f"  {GREEN}Damage Assessment:{RESET}")
    print(f"  {GREEN}  - Attacks blocked: {len(attack_requests)}{RESET}")
    print(f"  {GREEN}  - Data exfiltrated: 0 records{RESET}")
    print(f"  {GREEN}  - Token cost prevented: ~$108,000/month{RESET}")
    print(f"  {GREEN}  - Time to detection: 1.2 seconds{RESET}")
    print(f"  {GREEN}  - Time to remediation: 3.5 seconds{RESET}")
    print()

    print(f"  {GREEN}Recovery Actions:{RESET}")
    simulate_log("API keys rotated for affected services", "INFO")
    simulate_log("Firewall rules updated with new blocklist", "INFO")
    simulate_log("Audit trail exported to compliance/audit-log.json", "INFO")
    simulate_log("Incident report generated: INC-2026-0411", "INFO")
    simulate_log("Slack notification sent to #security-alerts", "INFO")
    pause(1)

    # Summary
    print(f"\n{GREEN}{BOLD}{'='*60}")
    print(f"  DEMO COMPLETE - Total Time: ~3 minutes")
    print(f"{'='*60}{RESET}")
    print(f"""
  {CYAN}DevPulse protected your APIs with:{RESET}
  {CYAN}  1. Real-time OWASP pattern detection{RESET}
  {CYAN}  2. Autonomous kill switch (< 4 second response){RESET}
  {CYAN}  3. LLM cost anomaly detection (infinite loop caught){RESET}
  {CYAN}  4. Full audit trail for compliance{RESET}
  {CYAN}  5. Automated recovery and key rotation{RESET}

  {YELLOW}Ready to protect your APIs? Visit https://devpulse.io{RESET}
""")

    # Cost intelligence summary
    analytics = token_tracker.get_analytics()
    print(f"  {BLUE}Cost Intelligence Summary:{RESET}")
    print(f"  {BLUE}  Total cost tracked: ${analytics['summary']['total_cost']}{RESET}")
    print(f"  {BLUE}  Thinking tokens: {analytics['summary']['thinking_tokens']:,}{RESET}")
    print(f"  {BLUE}  Thinking cost %: {analytics['summary']['thinking_percentage']}%{RESET}")


if __name__ == "__main__":
    live_mode = "--live" in sys.argv
    run_demo(live_mode)
