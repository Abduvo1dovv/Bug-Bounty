"""
Super Monster v1.0.0 - Correlation Engine Module

Multi-target finding correlation engine that identifies:
- Same vulnerability across multiple targets (SAME_VULN_MULTI_TARGET)
- Multi-step attack chains (ATTACK_CHAIN)
- Shared infrastructure patterns (SHARED_INFRASTRUCTURE)
- Cookie scope attacks across subdomains (COOKIE_SCOPE_ATTACK)
- Technology stack correlation (TECH_STACK_CORRELATION)
- Severity escalation paths (ESCALATION_PATH)

Core features:
- Correlation graph: nodes=findings, edges=correlations with confidence
- Confidence scoring (0.0-1.0) for each correlation
- Composite finding generation when confidence > 0.7
- ASCII attack chain visualization
- Rule engine with configurable correlation rules
- Graph traversal for attack path finding
- JSON output: correlation_report.json, attack_chains.md, escalated_findings.json
"""

import json
import hashlib
import os
import re
import sys
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

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
    Colors, CORRELATION_RULES, CONFIDENCE_THRESHOLDS, DOMAIN_TIERS,
    SCORING_WEIGHTS, SEVERITY_LEVELS, SEVERITY_ORDER, TOOL_BANNER,
    FINDING_TYPE_SEVERITY_MAP, CWE_MAPPING, BOUNTY_ESTIMATES,
    CORRELATION_BONUS_MULTIPLIERS, DEFAULT_OUTPUT_DIR,
    get_domain_tier, get_severity_from_cvss,
)
from super_monster.finding_db import FindingDB, Finding


# =============================================================================
# CONSTANTS AND ENUMERATIONS
# =============================================================================

CORRELATION_TYPE_SAME_VULN_MULTI_TARGET = "SAME_VULN_MULTI_TARGET"
CORRELATION_TYPE_ATTACK_CHAIN = "ATTACK_CHAIN"
CORRELATION_TYPE_SHARED_INFRASTRUCTURE = "SHARED_INFRASTRUCTURE"
CORRELATION_TYPE_COOKIE_SCOPE_ATTACK = "COOKIE_SCOPE_ATTACK"
CORRELATION_TYPE_TECH_STACK_CORRELATION = "TECH_STACK_CORRELATION"
CORRELATION_TYPE_ESCALATION_PATH = "ESCALATION_PATH"

ALL_CORRELATION_TYPES = [
    CORRELATION_TYPE_SAME_VULN_MULTI_TARGET,
    CORRELATION_TYPE_ATTACK_CHAIN,
    CORRELATION_TYPE_SHARED_INFRASTRUCTURE,
    CORRELATION_TYPE_COOKIE_SCOPE_ATTACK,
    CORRELATION_TYPE_TECH_STACK_CORRELATION,
    CORRELATION_TYPE_ESCALATION_PATH,
]

# Severity escalation matrix: (type1, type2) -> escalated_severity
ESCALATION_MATRIX = {
    ("cors", "cookie_flags"): "HIGH",
    ("cors", "session_fixation"): "HIGH",
    ("missing_headers", "cors"): "MEDIUM",
    ("missing_headers", "cookie_flags"): "MEDIUM",
    ("open_redirect", "xss_reflected"): "HIGH",
    ("open_redirect", "csrf"): "MEDIUM",
    ("info_disclosure", "auth_bypass"): "CRITICAL",
    ("info_disclosure", "idor"): "HIGH",
    ("xss_reflected", "csrf"): "HIGH",
    ("xss_stored", "session_hijack"): "CRITICAL",
    ("ssrf", "cloud_metadata"): "CRITICAL",
    ("ssrf", "info_disclosure"): "HIGH",
    ("subdomain_takeover", "cookie_flags"): "HIGH",
    ("subdomain_takeover", "cors"): "HIGH",
    ("path_traversal", "info_disclosure"): "HIGH",
    ("sqli", "data_exposure"): "CRITICAL",
    ("sqli", "auth_bypass"): "CRITICAL",
    ("idor", "pii_leak"): "CRITICAL",
    ("race_condition", "payment_bypass"): "CRITICAL",
    ("header_injection", "cache_poisoning"): "HIGH",
    ("file_upload", "rce"): "CRITICAL",
    ("jwt_vulnerability", "auth_bypass"): "CRITICAL",
    ("graphql_introspection", "idor"): "HIGH",
    ("version_disclosure", "rce"): "CRITICAL",
    ("directory_listing", "backup_file"): "MEDIUM",
    ("debug_endpoint", "info_disclosure"): "HIGH",
    ("weak_password", "auth_bypass"): "HIGH",
    ("default_credentials", "admin_access"): "CRITICAL",
    ("cors", "xss_stored"): "HIGH",
    ("missing_headers", "xss_reflected"): "MEDIUM",
    ("cookie_flags", "session_hijack"): "HIGH",
    ("tls_misconfiguration", "session_hijack"): "HIGH",
}

# Infrastructure fingerprint patterns
INFRASTRUCTURE_PATTERNS = {
    "cloudflare": ['cloudflare', 'cf-ray', '1\\.1\\.1\\.1'],
    "aws": ['amazonaws\\.com', 'cloudfront\\.net', 'elasticbeanstalk'],
    "gcp": ['googleapis\\.com', 'appspot\\.com', 'cloud\\.google'],
    "azure": ['azurewebsites\\.net', 'azure\\.com', 'microsoftonline'],
    "akamai": ['akamai', 'akamaiedge', 'edgekey\\.net'],
    "fastly": ['fastly\\.net', 'fastcdn\\.org'],
    "nginx": ['nginx', 'openresty'],
    "apache": ['apache', 'httpd'],
    "iis": ['microsoft-iis', 'asp\\.net'],
    "heroku": ['herokuapp\\.com', 'herokussl\\.com'],
    "vercel": ['vercel\\.app', 'now\\.sh'],
    "netlify": ['netlify\\.app', 'netlify\\.com'],
}

# Technology detection patterns
TECH_STACK_PATTERNS = {
    "react": ['react', '_next', '__NEXT_DATA__'],
    "angular": ['angular', 'ng-', 'zone\\.js'],
    "vue": ['vue\\.js', 'vuex', '__vue__'],
    "django": ['csrfmiddlewaretoken', 'django'],
    "rails": ['rails', 'authenticity_token'],
    "spring": ['spring', 'jsessionid'],
    "express": ['express', 'connect\\.sid'],
    "laravel": ['laravel', 'XSRF-TOKEN'],
    "wordpress": ['wp-content', 'wp-admin', 'wp-includes'],
    "drupal": ['drupal', 'sites/default'],
    "joomla": ['joomla', 'com_content'],
    "tomcat": ['tomcat', 'catalina'],
    "flask": ['flask', 'werkzeug'],
    "dotnet": ['asp\\.net', '__VIEWSTATE', '__EVENTVALIDATION'],
    "nodejs": ['node\\.js', 'express'],
    "php": ['PHPSESSID', '\\.php', 'X-Powered-By.*PHP'],
    "java": ['JSESSIONID', 'java', '\\.jsp'],
}

COOKIE_SCOPE_KEYWORDS = [
    "session", "token", "auth", "login", "csrf",
    "jwt", "access", "refresh", "remember", "sid",
]

GRAPH_CHARS = {
    "node": "[*]",
    "edge": "---",
    "arrow": "==>",
    "branch": "|--",
    "continue": "|  ",
    "end": "`--",
    "horizontal": "---",
    "vertical": "|",
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CorrelationEdge:
    """Represents a correlation between two findings (graph edge)."""
    id: str = ""
    source_id: str = ""
    target_id: str = ""
    correlation_type: str = ""
    confidence: float = 0.0
    description: str = ""
    evidence: str = ""
    created_at: str = ""
    rule_name: str = ""
    severity_impact: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert edge to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CorrelationEdge":
        """Create an edge from dictionary."""
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class CorrelationNode:
    """Represents a finding in the correlation graph (graph node)."""
    finding_id: str = ""
    finding_type: str = ""
    severity: str = ""
    domain: str = ""
    url: str = ""
    title: str = ""
    cvss_score: float = 0.0
    edges: list = field(default_factory=list)
    cluster_id: str = ""
    visited: bool = False
    depth: int = 0
    parent_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary."""
        return asdict(self)


@dataclass
class AttackChain:
    """Represents a multi-step attack chain."""
    id: str = ""
    title: str = ""
    description: str = ""
    steps: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    finding_ids: list = field(default_factory=list)
    total_confidence: float = 0.0
    escalated_severity: str = ""
    original_max_severity: str = ""
    domains: list = field(default_factory=list)
    attack_vector: str = ""
    impact: str = ""
    prerequisites: list = field(default_factory=list)
    created_at: str = ""
    correlation_type: str = ""
    estimated_bounty: float = 0.0
    visualization: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert chain to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackChain":
        """Create a chain from dictionary."""
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class CorrelationCluster:
    """A cluster of related findings."""
    id: str = ""
    name: str = ""
    finding_ids: list = field(default_factory=list)
    correlation_type: str = ""
    confidence: float = 0.0
    domains: list = field(default_factory=list)
    max_severity: str = ""
    description: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert cluster to dictionary."""
        return asdict(self)



# =============================================================================
# CORRELATION GRAPH CLASS
# =============================================================================

class CorrelationGraph:
    """
    Graph data structure for finding correlations.
    
    Nodes represent findings, edges represent correlations with
    confidence scores and type metadata. Supports BFS/DFS traversal,
    connected component detection, path finding, and centrality analysis.
    """

    def __init__(self):
        """Initialize empty correlation graph."""
        self.nodes: Dict[str, CorrelationNode] = {}
        self.edges: Dict[str, CorrelationEdge] = {}
        self.adjacency: Dict[str, List[str]] = defaultdict(list)
        self.reverse_adjacency: Dict[str, List[str]] = defaultdict(list)
        self.clusters: Dict[str, CorrelationCluster] = {}
        self._edge_index: Dict[Tuple[str, str], str] = {}
        self._type_index: Dict[str, List[str]] = defaultdict(list)
        self._domain_index: Dict[str, List[str]] = defaultdict(list)
        self._severity_index: Dict[str, List[str]] = defaultdict(list)

    def add_node(self, finding: Finding) -> str:
        """
        Add a finding as a node in the graph.

        Args:
            finding: The Finding object to add as a graph node.

        Returns:
            The node ID (same as finding ID).
        """
        node_id = finding.id
        if node_id in self.nodes:
            return node_id

        node = CorrelationNode(
            finding_id=finding.id,
            finding_type=finding.finding_type,
            severity=finding.severity,
            domain=finding.domain,
            url=finding.url,
            title=finding.title,
            cvss_score=finding.cvss_score,
        )
        self.nodes[node_id] = node
        self._type_index[finding.finding_type].append(node_id)
        self._domain_index[finding.domain].append(node_id)
        self._severity_index[finding.severity].append(node_id)
        return node_id

    def add_edge(self, source_id: str, target_id: str,
                 correlation_type: str, confidence: float,
                 description: str = "", evidence: str = "",
                 rule_name: str = "", severity_impact: str = "",
                 metadata: dict = None) -> Optional[str]:
        """
        Add a correlation edge between two findings.

        Args:
            source_id: Source finding ID.
            target_id: Target finding ID.
            correlation_type: Type of correlation.
            confidence: Confidence score (0.0-1.0).
            description: Human-readable description of the correlation.
            evidence: Evidence text supporting this correlation.
            rule_name: Name of the rule that triggered this correlation.
            severity_impact: How this correlation affects severity.
            metadata: Additional metadata dictionary.

        Returns:
            Edge ID if created, None if invalid (missing nodes or self-loop).
        """
        if source_id not in self.nodes or target_id not in self.nodes:
            return None
        if source_id == target_id:
            return None

        edge_key = (min(source_id, target_id), max(source_id, target_id))
        if edge_key in self._edge_index:
            existing_edge_id = self._edge_index[edge_key]
            existing = self.edges.get(existing_edge_id)
            if existing and confidence > existing.confidence:
                existing.confidence = confidence
                existing.correlation_type = correlation_type
                existing.description = description
                existing.evidence = evidence
            return existing_edge_id

        edge_id = f"CORR-{uuid.uuid4().hex[:10].upper()}"
        edge = CorrelationEdge(
            id=edge_id,
            source_id=source_id,
            target_id=target_id,
            correlation_type=correlation_type,
            confidence=confidence,
            description=description,
            evidence=evidence,
            created_at=datetime.utcnow().isoformat(),
            rule_name=rule_name,
            severity_impact=severity_impact,
            metadata=metadata or {},
        )

        self.edges[edge_id] = edge
        self.adjacency[source_id].append(edge_id)
        self.adjacency[target_id].append(edge_id)
        self.reverse_adjacency[target_id].append(source_id)
        self.reverse_adjacency[source_id].append(target_id)
        self._edge_index[edge_key] = edge_id
        self.nodes[source_id].edges.append(edge_id)
        self.nodes[target_id].edges.append(edge_id)

        return edge_id

    def get_neighbors(self, node_id: str) -> List[str]:
        """Get all neighboring node IDs for a given node."""
        neighbors = set()
        for edge_id in self.adjacency.get(node_id, []):
            edge = self.edges.get(edge_id)
            if edge:
                if edge.source_id == node_id:
                    neighbors.add(edge.target_id)
                else:
                    neighbors.add(edge.source_id)
        return list(neighbors)

    def get_edges_for_node(self, node_id: str) -> List[CorrelationEdge]:
        """Get all edges connected to a specific node."""
        edge_ids = self.adjacency.get(node_id, [])
        return [self.edges[eid] for eid in edge_ids if eid in self.edges]

    def get_edge_between(self, node_a: str, node_b: str) -> Optional[CorrelationEdge]:
        """Get the edge between two specific nodes, if it exists."""
        edge_key = (min(node_a, node_b), max(node_a, node_b))
        edge_id = self._edge_index.get(edge_key)
        if edge_id:
            return self.edges.get(edge_id)
        return None

    def get_nodes_by_type(self, finding_type: str) -> List[str]:
        """Get all node IDs with a given finding type."""
        return self._type_index.get(finding_type, [])

    def get_nodes_by_domain(self, domain: str) -> List[str]:
        """Get all node IDs for a given domain."""
        return self._domain_index.get(domain, [])

    def get_nodes_by_severity(self, severity: str) -> List[str]:
        """Get all node IDs with a given severity level."""
        return self._severity_index.get(severity, [])

    def find_connected_components(self) -> List[List[str]]:
        """
        Find all connected components in the graph using BFS.
        Only returns components with 2+ nodes (isolated nodes excluded).

        Returns:
            List of connected components sorted by size (largest first).
        """
        visited: Set[str] = set()
        components: List[List[str]] = []

        for node_id in self.nodes:
            if node_id in visited:
                continue
            component = []
            queue = [node_id]
            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                component.append(current)
                for neighbor in self.get_neighbors(current):
                    if neighbor not in visited:
                        queue.append(neighbor)
            if len(component) > 1:
                components.append(component)

        return sorted(components, key=len, reverse=True)

    def find_paths(self, start_id: str, end_id: str, max_depth: int = 6) -> List[List[str]]:
        """
        Find all paths between two nodes using DFS with depth limit.

        Args:
            start_id: Starting node ID.
            end_id: Ending node ID.
            max_depth: Maximum path depth to prevent runaway recursion.

        Returns:
            List of paths, each a list of node IDs from start to end.
        """
        all_paths: List[List[str]] = []

        def _dfs(current: str, target: str, path: List[str], visited: Set[str], depth: int):
            if depth > max_depth:
                return
            if current == target:
                all_paths.append(path[:])
                return
            for neighbor in self.get_neighbors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    path.append(neighbor)
                    _dfs(neighbor, target, path, visited, depth + 1)
                    path.pop()
                    visited.discard(neighbor)

        visited_set = {start_id}
        _dfs(start_id, end_id, [start_id], visited_set, 0)
        return all_paths

    def find_longest_path(self, start_id: str) -> List[str]:
        """Find the longest path from a starting node using BFS."""
        if start_id not in self.nodes:
            return []
        longest = [start_id]
        queue = [(start_id, [start_id])]
        visited = {start_id}
        while queue:
            current, path = queue.pop(0)
            for neighbor in self.get_neighbors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    new_path = path + [neighbor]
                    queue.append((neighbor, new_path))
                    if len(new_path) > len(longest):
                        longest = new_path
        return longest

    def calculate_node_centrality(self, node_id: str) -> float:
        """Calculate degree centrality for a node (0.0-1.0)."""
        if node_id not in self.nodes or len(self.nodes) <= 1:
            return 0.0
        degree = len(self.adjacency.get(node_id, []))
        max_possible = len(self.nodes) - 1
        return degree / max_possible if max_possible > 0 else 0.0

    def calculate_betweenness_centrality(self, node_id: str) -> float:
        """Approximate betweenness centrality using BFS sampling."""
        if node_id not in self.nodes or len(self.nodes) <= 2:
            return 0.0
        all_nodes = list(self.nodes.keys())
        sample_size = min(30, len(all_nodes))
        sampled = all_nodes[:sample_size]
        path_count = 0
        through_count = 0
        for i, src in enumerate(sampled):
            if src == node_id:
                continue
            for dst in sampled[i+1:]:
                if dst == node_id:
                    continue
                paths = self.find_paths(src, dst, max_depth=4)
                if paths:
                    path_count += 1
                    for path in paths:
                        if node_id in path[1:-1]:
                            through_count += 1
                            break
        return through_count / max(path_count, 1)

    def get_high_centrality_nodes(self, top_n: int = 10) -> List[Tuple[str, float]]:
        """Get the nodes with highest degree centrality scores."""
        centralities = []
        for node_id in self.nodes:
            score = self.calculate_node_centrality(node_id)
            centralities.append((node_id, score))
        centralities.sort(key=lambda x: x[1], reverse=True)
        return centralities[:top_n]

    def get_subgraph(self, node_ids: List[str]) -> "CorrelationGraph":
        """Extract a subgraph containing only specified nodes and connecting edges."""
        subgraph = CorrelationGraph()
        node_set = set(node_ids)
        for nid in node_ids:
            if nid in self.nodes:
                node = self.nodes[nid]
                sub_node = CorrelationNode(
                    finding_id=node.finding_id,
                    finding_type=node.finding_type,
                    severity=node.severity,
                    domain=node.domain,
                    url=node.url,
                    title=node.title,
                    cvss_score=node.cvss_score,
                )
                subgraph.nodes[nid] = sub_node
                subgraph._type_index[node.finding_type].append(nid)
                subgraph._domain_index[node.domain].append(nid)
        for edge_id, edge in self.edges.items():
            if edge.source_id in node_set and edge.target_id in node_set:
                subgraph.edges[edge_id] = edge
                subgraph.adjacency[edge.source_id].append(edge_id)
                subgraph.adjacency[edge.target_id].append(edge_id)
                key = (min(edge.source_id, edge.target_id), max(edge.source_id, edge.target_id))
                subgraph._edge_index[key] = edge_id
        return subgraph

    def node_count(self) -> int:
        """Get total number of nodes in the graph."""
        return len(self.nodes)

    def edge_count(self) -> int:
        """Get total number of edges in the graph."""
        return len(self.edges)

    def density(self) -> float:
        """Calculate graph density."""
        n = self.node_count()
        if n <= 1:
            return 0.0
        max_edges = n * (n - 1) / 2
        return self.edge_count() / max_edges if max_edges > 0 else 0.0

    def get_isolated_nodes(self) -> List[str]:
        """Get nodes with no connections."""
        return [nid for nid in self.nodes if not self.adjacency.get(nid)]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the complete graph to a dictionary."""
        return {
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "edges": {eid: e.to_dict() for eid, e in self.edges.items()},
            "clusters": {cid: c.to_dict() for cid, c in self.clusters.items()},
            "statistics": {
                "node_count": self.node_count(),
                "edge_count": self.edge_count(),
                "density": round(self.density(), 4),
                "components": len(self.find_connected_components()),
                "isolated_nodes": len(self.get_isolated_nodes()),
            },
        }


# =============================================================================
# CORRELATION RULE ENGINE
# =============================================================================

class CorrelationRuleEngine:
    """
    Rule-based correlation engine that applies configurable rules
    to identify patterns across findings.
    
    Supports built-in rules (from config), custom runtime rules,
    pattern-based matching, and heuristic confidence scoring.
    """

    def __init__(self, custom_rules: Dict[str, Any] = None):
        """
        Initialize the rule engine with built-in and custom rules.

        Args:
            custom_rules: Additional rules to merge with built-in rules.
        """
        self.rules: Dict[str, Any] = dict(CORRELATION_RULES)
        if custom_rules:
            self.rules.update(custom_rules)
        self.rule_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"matches": 0, "skipped": 0, "errors": 0}
        )
        self._compiled_patterns: Dict[str, List] = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns for performance."""
        for rule_name, rule_config in self.rules.items():
            patterns = rule_config.get("url_patterns", [])
            compiled = []
            for pattern in patterns:
                try:
                    compiled.append(re.compile(pattern, re.IGNORECASE))
                except re.error:
                    continue
            self._compiled_patterns[rule_name] = compiled

    def add_rule(self, name: str, rule_config: Dict[str, Any]) -> None:
        """Add a custom correlation rule at runtime."""
        self.rules[name] = rule_config
        patterns = rule_config.get("url_patterns", [])
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                continue
        self._compiled_patterns[name] = compiled

    def remove_rule(self, name: str) -> bool:
        """Remove a rule by name. Returns True if removed."""
        if name in self.rules:
            del self.rules[name]
            self._compiled_patterns.pop(name, None)
            return True
        return False

    def evaluate_rule(self, rule_name: str, findings: List[Finding],
                      domain_findings: Dict[str, List[Finding]]) -> List[Dict[str, Any]]:
        """
        Evaluate a single rule against the findings set.

        Args:
            rule_name: Name of the rule to evaluate.
            findings: All available findings.
            domain_findings: Findings pre-grouped by domain.

        Returns:
            List of match results with finding IDs and confidence scores.
        """
        rule_config = self.rules.get(rule_name)
        if not rule_config:
            return []

        required_types = set(rule_config.get("required_types", []))
        optional_types = set(rule_config.get("optional_types", []))
        min_findings_count = rule_config.get("min_findings", 2)
        confidence_threshold = rule_config.get("confidence_threshold", 0.7)

        matches = []

        # Check by domain grouping
        for domain, domain_flist in domain_findings.items():
            domain_required = [f for f in domain_flist if f.finding_type in required_types]
            domain_optional = [f for f in domain_flist if f.finding_type in optional_types]

            if len(domain_required) < 1:
                continue

            # Calculate confidence for this domain match
            confidence = self._calculate_rule_confidence(
                domain_required, domain_optional, rule_config, domain
            )

            if confidence >= confidence_threshold:
                match_result = {
                    "rule_name": rule_name,
                    "domain": domain,
                    "required_findings": [f.id for f in domain_required],
                    "optional_findings": [f.id for f in domain_optional[:5]],
                    "all_finding_ids": [f.id for f in domain_required + domain_optional[:5]],
                    "confidence": round(confidence, 4),
                    "severity_boost": rule_config.get("severity_boost", "HIGH"),
                    "chain_description": rule_config.get("chain_description", ""),
                    "description": rule_config.get("description", ""),
                }
                matches.append(match_result)
                self.rule_stats[rule_name]["matches"] += 1

        if not matches:
            self.rule_stats[rule_name]["skipped"] += 1

        return matches

    def evaluate_all_rules(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        Evaluate all rules against the findings set.

        Args:
            findings: Complete list of findings to analyze.

        Returns:
            All matches across all rules, sorted by confidence descending.
        """
        domain_findings: Dict[str, List[Finding]] = defaultdict(list)
        for f in findings:
            domain_findings[f.domain or "unknown"].append(f)

        all_matches = []
        for rule_name in self.rules:
            try:
                rule_matches = self.evaluate_rule(rule_name, findings, domain_findings)
                all_matches.extend(rule_matches)
            except Exception:
                self.rule_stats[rule_name]["errors"] += 1
                continue

        all_matches.sort(key=lambda m: m["confidence"], reverse=True)
        return all_matches

    def _calculate_rule_confidence(self, required: List[Finding],
                                    optional: List[Finding],
                                    rule_config: Dict[str, Any],
                                    domain: str) -> float:
        """
        Calculate confidence score for a rule match.

        Factors in: required count, optional count, CVSS scores,
        domain relationships, and evidence quality.
        """
        confidence = 0.5

        min_required = rule_config.get("min_findings", 2)
        if len(required) >= min_required:
            confidence += 0.15
        if len(required) >= min_required * 2:
            confidence += 0.10
        if len(required) >= min_required * 3:
            confidence += 0.05

        if optional:
            confidence += min(len(optional) * 0.05, 0.15)

        all_cvss = [f.cvss_score for f in required + optional if f.cvss_score > 0]
        if all_cvss:
            avg_cvss = sum(all_cvss) / len(all_cvss)
            if avg_cvss >= 8.0:
                confidence += 0.10
            elif avg_cvss >= 6.0:
                confidence += 0.05

        domains = set(f.domain for f in required + optional if f.domain)
        if len(domains) == 1:
            confidence += 0.08

        evidence_boost = 0.0
        for f in required:
            if f.evidence and len(f.evidence) > 100:
                evidence_boost += 0.03
            elif f.evidence and len(f.evidence) > 50:
                evidence_boost += 0.02
        confidence += min(evidence_boost, 0.10)

        return min(confidence, 0.99)

    def get_rule_statistics(self) -> Dict[str, Dict[str, int]]:
        """Get statistics about rule evaluation performance."""
        return dict(self.rule_stats)

    def get_active_rules(self) -> List[str]:
        """Get list of active rule names."""
        return list(self.rules.keys())

    def get_rule_config(self, rule_name: str) -> Optional[Dict[str, Any]]:
        """Get configuration for a specific rule."""
        return self.rules.get(rule_name)

    def reset_stats(self) -> None:
        """Reset all rule statistics."""
        self.rule_stats.clear()


# =============================================================================
# MAIN CORRELATION ENGINE
# =============================================================================

class CorrelationEngine:
    """
    Main correlation engine that orchestrates finding analysis.
    
    Integrates the CorrelationGraph, RuleEngine, and various correlation
    detection algorithms to produce a comprehensive correlation report.
    
    Usage:
        engine = CorrelationEngine()
        engine.load_findings_from_db(db)
        engine.run_full_analysis()
        engine.generate_report(output_dir)
    """

    def __init__(self, db: FindingDB = None, custom_rules: Dict[str, Any] = None,
                 min_confidence: float = 0.6, output_dir: str = None):
        """
        Initialize the correlation engine.

        Args:
            db: FindingDB instance to load findings from.
            custom_rules: Additional correlation rules.
            min_confidence: Minimum confidence threshold for reporting.
            output_dir: Directory for output files.
        """
        self.db = db
        self.graph = CorrelationGraph()
        self.rule_engine = CorrelationRuleEngine(custom_rules)
        self.min_confidence = min_confidence
        self.output_dir = output_dir or DEFAULT_OUTPUT_DIR
        self.findings: List[Finding] = []
        self.attack_chains: List[AttackChain] = []
        self.escalated_findings: List[Dict[str, Any]] = []
        self.correlation_edges: List[CorrelationEdge] = []
        self.clusters: List[CorrelationCluster] = []
        self._domain_map: Dict[str, List[Finding]] = defaultdict(list)
        self._type_map: Dict[str, List[Finding]] = defaultdict(list)
        self._url_map: Dict[str, List[Finding]] = defaultdict(list)
        self._infra_map: Dict[str, List[str]] = defaultdict(list)
        self._tech_map: Dict[str, List[str]] = defaultdict(list)
        self.stats: Dict[str, Any] = {
            "total_findings": 0,
            "total_correlations": 0,
            "total_chains": 0,
            "total_escalated": 0,
            "correlation_types": defaultdict(int),
            "processing_time": 0.0,
        }

    def load_findings_from_db(self, db: FindingDB = None) -> int:
        """
        Load all findings from the database into the engine.

        Args:
            db: Optional FindingDB override. Uses self.db if not provided.

        Returns:
            Number of findings loaded.
        """
        if db:
            self.db = db
        if not self.db:
            return 0

        self.findings = self.db.get_all()
        self._build_indexes()
        self._build_graph()
        self.stats["total_findings"] = len(self.findings)
        return len(self.findings)

    def load_findings_from_reports(self, input_path: str) -> int:
        """
        Load findings directly from Monster JSON report files.

        Args:
            input_path: Path to a report file or directory of reports.

        Returns:
            Number of findings loaded.
        """
        if not self.db:
            self.db = FindingDB()

        if os.path.isdir(input_path):
            self.db.import_directory(input_path)
        elif os.path.isfile(input_path):
            self.db.import_monster_report(input_path)

        return self.load_findings_from_db()

    def _build_indexes(self):
        """Build internal lookup indexes from loaded findings."""
        self._domain_map.clear()
        self._type_map.clear()
        self._url_map.clear()
        self._infra_map.clear()
        self._tech_map.clear()

        for finding in self.findings:
            self._domain_map[finding.domain or "unknown"].append(finding)
            self._type_map[finding.finding_type].append(finding)
            
            # Parse URL for path-level grouping
            if finding.url:
                try:
                    parsed = urlparse(finding.url)
                    url_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    self._url_map[url_key].append(finding)
                except Exception:
                    pass

            # Detect infrastructure from evidence
            self._detect_infrastructure(finding)
            # Detect technology stack
            self._detect_tech_stack(finding)

    def _build_graph(self):
        """Build the correlation graph from loaded findings."""
        self.graph = CorrelationGraph()
        for finding in self.findings:
            self.graph.add_node(finding)

    def _detect_infrastructure(self, finding: Finding):
        """Detect infrastructure provider from finding evidence and URL."""
        searchable = " ".join([
            finding.evidence or "",
            finding.url or "",
            finding.description or "",
        ]).lower()

        for infra_name, patterns in INFRASTRUCTURE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, searchable, re.IGNORECASE):
                    if finding.id not in self._infra_map[infra_name]:
                        self._infra_map[infra_name].append(finding.id)
                    break

    def _detect_tech_stack(self, finding: Finding):
        """Detect technology stack from finding evidence."""
        searchable = " ".join([
            finding.evidence or "",
            finding.url or "",
            finding.description or "",
        ]).lower()

        for tech_name, patterns in TECH_STACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, searchable, re.IGNORECASE):
                    if finding.id not in self._tech_map[tech_name]:
                        self._tech_map[tech_name].append(finding.id)
                    break

    # =========================================================================
    # CORRELATION DETECTION METHODS
    # =========================================================================

    def detect_same_vuln_multi_target(self) -> List[CorrelationEdge]:
        """
        Detect SAME_VULN_MULTI_TARGET correlations.
        
        Identifies when the same vulnerability type appears on multiple
        different hosts/domains, suggesting a systemic issue.

        Returns:
            List of correlation edges created.
        """
        edges_created = []

        for finding_type, findings_of_type in self._type_map.items():
            if len(findings_of_type) < 2:
                continue

            # Group by domain to find cross-domain occurrences
            domains_with_type: Dict[str, List[Finding]] = defaultdict(list)
            for f in findings_of_type:
                domains_with_type[f.domain or "unknown"].append(f)

            if len(domains_with_type) < 2:
                continue

            # Create correlations between findings of same type on different domains
            domain_list = list(domains_with_type.keys())
            for i in range(len(domain_list)):
                for j in range(i + 1, len(domain_list)):
                    d1_findings = domains_with_type[domain_list[i]]
                    d2_findings = domains_with_type[domain_list[j]]

                    # Take representative finding from each domain
                    for f1 in d1_findings[:3]:
                        for f2 in d2_findings[:3]:
                            confidence = self._calc_same_vuln_confidence(f1, f2)
                            if confidence >= self.min_confidence:
                                description = (
                                    f"{finding_type} found on both "
                                    f"{f1.domain} and {f2.domain}"
                                )
                                edge_id = self.graph.add_edge(
                                    source_id=f1.id,
                                    target_id=f2.id,
                                    correlation_type=CORRELATION_TYPE_SAME_VULN_MULTI_TARGET,
                                    confidence=confidence,
                                    description=description,
                                    evidence=f"Same type: {finding_type}",
                                    rule_name="same_vuln_multi_target",
                                    severity_impact="systemic",
                                )
                                if edge_id:
                                    edge = self.graph.edges[edge_id]
                                    edges_created.append(edge)

        self.stats["correlation_types"]["SAME_VULN_MULTI_TARGET"] = len(edges_created)
        return edges_created

    def _calc_same_vuln_confidence(self, f1: Finding, f2: Finding) -> float:
        """Calculate confidence for same-vuln-multi-target correlation."""
        confidence = 0.5

        # Same finding type is the base
        if f1.finding_type == f2.finding_type:
            confidence += 0.2

        # Same CWE ID increases confidence
        if f1.cwe_id and f2.cwe_id and f1.cwe_id == f2.cwe_id:
            confidence += 0.1

        # Similar CVSS scores suggest same vuln class
        if abs(f1.cvss_score - f2.cvss_score) < 1.0:
            confidence += 0.05

        # Same severity
        if f1.severity == f2.severity:
            confidence += 0.05

        # Evidence similarity (basic check)
        if f1.evidence and f2.evidence:
            e1_words = set(f1.evidence.lower().split()[:20])
            e2_words = set(f2.evidence.lower().split()[:20])
            if e1_words and e2_words:
                overlap = len(e1_words & e2_words) / max(len(e1_words | e2_words), 1)
                confidence += overlap * 0.1

        return min(confidence, 0.99)

    def detect_attack_chains(self) -> List[AttackChain]:
        """
        Detect ATTACK_CHAIN correlations using the rule engine.
        
        Combines multiple findings into multi-step attack paths that
        escalate severity beyond individual findings.

        Returns:
            List of attack chains detected.
        """
        chains_detected = []

        # Use rule engine to find matches
        rule_matches = self.rule_engine.evaluate_all_rules(self.findings)

        for match in rule_matches:
            if match["confidence"] < self.min_confidence:
                continue

            finding_ids = match["all_finding_ids"]
            if len(finding_ids) < 2:
                continue

            # Create edges between chain members
            for i in range(len(finding_ids)):
                for j in range(i + 1, len(finding_ids)):
                    self.graph.add_edge(
                        source_id=finding_ids[i],
                        target_id=finding_ids[j],
                        correlation_type=CORRELATION_TYPE_ATTACK_CHAIN,
                        confidence=match["confidence"],
                        description=match.get("chain_description", ""),
                        rule_name=match["rule_name"],
                        severity_impact=match.get("severity_boost", "HIGH"),
                    )

            # Build attack chain object
            chain_findings = [self.db.get_finding(fid) for fid in finding_ids if self.db.get_finding(fid)]
            if not chain_findings:
                continue

            chain = self._build_attack_chain(
                findings=chain_findings,
                rule_match=match,
            )
            if chain:
                chains_detected.append(chain)

        self.stats["correlation_types"]["ATTACK_CHAIN"] = len(chains_detected)
        return chains_detected

    def _build_attack_chain(self, findings: List[Finding],
                            rule_match: Dict[str, Any]) -> Optional[AttackChain]:
        """Build an AttackChain object from correlated findings."""
        if not findings:
            return None

        # Determine severity order for chain steps
        sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.severity, 0))

        # Build steps
        steps = []
        for i, f in enumerate(sorted_findings):
            step = {
                "step_number": i + 1,
                "finding_id": f.id,
                "finding_type": f.finding_type,
                "title": f.title,
                "severity": f.severity,
                "domain": f.domain,
                "url": f.url,
                "description": f"Step {i+1}: Exploit {f.finding_type} on {f.domain}",
            }
            steps.append(step)

        # Calculate original max severity
        max_sev = max(findings, key=lambda f: sev_order.get(f.severity, 0))
        original_max = max_sev.severity

        # Determine escalated severity
        escalated = rule_match.get("severity_boost", original_max)

        # Get unique domains
        domains = list(set(f.domain for f in findings if f.domain))

        # Estimate bounty for chain
        bounty_config = BOUNTY_ESTIMATES.get(escalated, BOUNTY_ESTIMATES.get("HIGH"))
        estimated_bounty = bounty_config["median"] if bounty_config else 5000

        # Generate chain title
        chain_title = rule_match.get("description", "Attack Chain")
        if domains:
            chain_title += f" ({', '.join(domains[:3])})"

        chain = AttackChain(
            id=f"CHAIN-{uuid.uuid4().hex[:8].upper()}",
            title=chain_title,
            description=rule_match.get("chain_description", ""),
            steps=steps,
            findings=[f.to_dict() for f in findings],
            finding_ids=[f.id for f in findings],
            total_confidence=rule_match["confidence"],
            escalated_severity=escalated,
            original_max_severity=original_max,
            domains=domains,
            attack_vector=self._determine_attack_vector(findings),
            impact=self._assess_chain_impact(findings, escalated),
            prerequisites=self._determine_prerequisites(findings),
            created_at=datetime.utcnow().isoformat(),
            correlation_type=CORRELATION_TYPE_ATTACK_CHAIN,
            estimated_bounty=estimated_bounty,
            visualization=self._generate_chain_ascii(steps),
        )

        return chain

    def _determine_attack_vector(self, findings: List[Finding]) -> str:
        """Determine primary attack vector for a chain."""
        type_priorities = {
            "rce": "Remote Code Execution",
            "sqli": "SQL Injection",
            "auth_bypass": "Authentication Bypass",
            "ssrf": "Server-Side Request Forgery",
            "xss_stored": "Stored Cross-Site Scripting",
            "idor": "Insecure Direct Object Reference",
            "file_upload": "Unrestricted File Upload",
            "deserialization": "Insecure Deserialization",
        }
        for f in findings:
            if f.finding_type in type_priorities:
                return type_priorities[f.finding_type]
        return "Multi-vector attack chain"

    def _assess_chain_impact(self, findings: List[Finding], escalated_sev: str) -> str:
        """Assess the business impact of an attack chain."""
        impacts = {
            "CRITICAL": "Complete system compromise with potential data breach and service disruption",
            "HIGH": "Significant unauthorized access to sensitive data or functionality",
            "MEDIUM": "Limited unauthorized access or data exposure",
            "LOW": "Minor information leakage with limited impact",
            "INFO": "Informational chain with minimal direct impact",
        }
        return impacts.get(escalated_sev, "Unknown impact level")

    def _determine_prerequisites(self, findings: List[Finding]) -> List[str]:
        """Determine prerequisites for exploiting an attack chain."""
        prereqs = set()
        for f in findings:
            if f.finding_type in ("auth_bypass", "credential_exposure"):
                prereqs.add("Valid target URL accessible from attacker network")
            elif f.finding_type in ("xss_stored", "csrf"):
                prereqs.add("Victim must visit attacker-controlled page or link")
            elif f.finding_type in ("ssrf",):
                prereqs.add("Access to parameter that triggers server-side requests")
            elif f.finding_type in ("sqli", "sqli_blind"):
                prereqs.add("Injectable parameter identified and accessible")
            elif f.finding_type in ("race_condition",):
                prereqs.add("Ability to send concurrent requests to the endpoint")
        if not prereqs:
            prereqs.add("Network access to target application")
        return list(prereqs)

    def detect_shared_infrastructure(self) -> List[CorrelationEdge]:
        """
        Detect SHARED_INFRASTRUCTURE correlations.
        
        Identifies findings on targets that share the same infrastructure
        (same CDN, cloud provider, IP range, SSL certificate SANs).

        Returns:
            List of correlation edges created.
        """
        edges_created = []

        for infra_name, finding_ids in self._infra_map.items():
            if len(finding_ids) < 2:
                continue

            # Cross-correlate findings sharing infrastructure
            for i in range(min(len(finding_ids), 20)):
                for j in range(i + 1, min(len(finding_ids), 20)):
                    fid1 = finding_ids[i]
                    fid2 = finding_ids[j]

                    f1 = self.db.get_finding(fid1) if self.db else None
                    f2 = self.db.get_finding(fid2) if self.db else None

                    if not f1 or not f2:
                        continue
                    if f1.domain == f2.domain:
                        continue

                    confidence = 0.55
                    if infra_name in ("aws", "gcp", "azure"):
                        confidence += 0.15
                    elif infra_name in ("cloudflare", "akamai", "fastly"):
                        confidence += 0.10
                    else:
                        confidence += 0.05

                    if confidence >= self.min_confidence:
                        edge_id = self.graph.add_edge(
                            source_id=fid1,
                            target_id=fid2,
                            correlation_type=CORRELATION_TYPE_SHARED_INFRASTRUCTURE,
                            confidence=confidence,
                            description=f"Shared {infra_name} infrastructure",
                            evidence=f"Both targets use {infra_name}",
                            rule_name="shared_infrastructure",
                            severity_impact="infrastructure",
                        )
                        if edge_id:
                            edges_created.append(self.graph.edges[edge_id])

        self.stats["correlation_types"]["SHARED_INFRASTRUCTURE"] = len(edges_created)
        return edges_created

    def detect_cookie_scope_attacks(self) -> List[CorrelationEdge]:
        """
        Detect COOKIE_SCOPE_ATTACK correlations.
        
        Identifies when cookies set for a parent domain (.domain.tld)
        are accessible from subdomain findings, enabling session theft.

        Returns:
            List of correlation edges created.
        """
        edges_created = []

        # Find cookie-related findings
        cookie_types = ["cookie_flags", "session_fixation", "session_hijack",
                       "cookie_theft", "missing_headers"]
        cookie_findings = []
        for ctype in cookie_types:
            cookie_findings.extend(self._type_map.get(ctype, []))

        if len(cookie_findings) < 2:
            return edges_created

        # Group by parent domain
        parent_domain_groups: Dict[str, List[Finding]] = defaultdict(list)
        for f in cookie_findings:
            parent = self._extract_parent_domain(f.domain or "")
            if parent:
                parent_domain_groups[parent].append(f)

        # Find subdomain takeover findings
        takeover_findings = self._type_map.get("subdomain_takeover", [])

        # Cross-correlate cookie issues with subdomain takeovers
        for parent_domain, cookie_group in parent_domain_groups.items():
            related_takeovers = [
                f for f in takeover_findings
                if self._extract_parent_domain(f.domain or "") == parent_domain
            ]

            # Cookie scope across subdomains
            if len(cookie_group) >= 2:
                for i in range(min(len(cookie_group), 10)):
                    for j in range(i + 1, min(len(cookie_group), 10)):
                        f1 = cookie_group[i]
                        f2 = cookie_group[j]
                        if f1.domain == f2.domain:
                            continue

                        confidence = 0.65
                        if any(kw in (f1.evidence or "").lower() for kw in COOKIE_SCOPE_KEYWORDS):
                            confidence += 0.10
                        if any(kw in (f2.evidence or "").lower() for kw in COOKIE_SCOPE_KEYWORDS):
                            confidence += 0.05

                        if confidence >= self.min_confidence:
                            edge_id = self.graph.add_edge(
                                source_id=f1.id,
                                target_id=f2.id,
                                correlation_type=CORRELATION_TYPE_COOKIE_SCOPE_ATTACK,
                                confidence=confidence,
                                description=f"Cookie scope attack across {parent_domain} subdomains",
                                evidence=f"Shared parent domain: {parent_domain}",
                                rule_name="cookie_scope_attack",
                                severity_impact="HIGH",
                            )
                            if edge_id:
                                edges_created.append(self.graph.edges[edge_id])

            # Combine with subdomain takeover
            for takeover in related_takeovers[:5]:
                for cookie_f in cookie_group[:5]:
                    confidence = 0.75
                    edge_id = self.graph.add_edge(
                        source_id=takeover.id,
                        target_id=cookie_f.id,
                        correlation_type=CORRELATION_TYPE_COOKIE_SCOPE_ATTACK,
                        confidence=confidence,
                        description="Subdomain takeover enables cookie theft via scope",
                        evidence=f"Takeover on {takeover.domain} + cookie on {cookie_f.domain}",
                        rule_name="cookie_scope_takeover",
                        severity_impact="HIGH",
                    )
                    if edge_id:
                        edges_created.append(self.graph.edges[edge_id])

        self.stats["correlation_types"]["COOKIE_SCOPE_ATTACK"] = len(edges_created)
        return edges_created

    def _extract_parent_domain(self, domain: str) -> str:
        """Extract the parent/root domain from a subdomain."""
        if not domain:
            return ""
        parts = domain.lower().strip().split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain

    def detect_tech_stack_correlation(self) -> List[CorrelationEdge]:
        """
        Detect TECH_STACK_CORRELATION patterns.
        
        When multiple targets share the same technology stack (framework,
        CMS, server), a vulnerability in one likely affects all others.

        Returns:
            List of correlation edges created.
        """
        edges_created = []

        for tech_name, finding_ids in self._tech_map.items():
            if len(finding_ids) < 2:
                continue

            # Group by domain
            domain_groups: Dict[str, List[str]] = defaultdict(list)
            for fid in finding_ids:
                node = self.graph.nodes.get(fid)
                if node:
                    domain_groups[node.domain].append(fid)

            if len(domain_groups) < 2:
                continue

            # Create correlations between different domains sharing tech
            domain_list = list(domain_groups.keys())
            if len(domain_list) > 10:
                print(
                    f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Tech stack correlation "
                    f"for '{tech_name}': {len(domain_list)} domains found but only "
                    f"first 10 will be analyzed. Results may be incomplete.",
                    file=sys.stderr,
                )
            for i in range(min(len(domain_list), 10)):
                for j in range(i + 1, min(len(domain_list), 10)):
                    d1_findings = domain_groups[domain_list[i]][:3]
                    d2_findings = domain_groups[domain_list[j]][:3]

                    for fid1 in d1_findings:
                        for fid2 in d2_findings:
                            confidence = 0.55
                            # Higher confidence for specific frameworks
                            if tech_name in ("wordpress", "drupal", "joomla"):
                                confidence += 0.20
                            elif tech_name in ("spring", "django", "rails", "laravel"):
                                confidence += 0.15
                            else:
                                confidence += 0.10

                            if confidence >= self.min_confidence:
                                edge_id = self.graph.add_edge(
                                    source_id=fid1,
                                    target_id=fid2,
                                    correlation_type=CORRELATION_TYPE_TECH_STACK_CORRELATION,
                                    confidence=confidence,
                                    description=f"Shared {tech_name} stack across domains",
                                    evidence=f"Technology: {tech_name}",
                                    rule_name="tech_stack_correlation",
                                    severity_impact="systemic",
                                )
                                if edge_id:
                                    edges_created.append(self.graph.edges[edge_id])

        self.stats["correlation_types"]["TECH_STACK_CORRELATION"] = len(edges_created)
        return edges_created

    def detect_escalation_paths(self) -> List[CorrelationEdge]:
        """
        Detect ESCALATION_PATH correlations.
        
        Identifies when two low/medium severity findings combine to create
        a higher severity issue (e.g., CORS + insecure cookie = session theft).

        Returns:
            List of correlation edges created.
        """
        edges_created = []

        # Check all pairs in the escalation matrix
        for (type1, type2), escalated_sev in ESCALATION_MATRIX.items():
            findings_type1 = self._type_map.get(type1, [])
            findings_type2 = self._type_map.get(type2, [])

            if not findings_type1 or not findings_type2:
                continue

            # Match within same domain or related domains
            if len(findings_type1) > 10:
                print(
                    f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Escalation path "
                    f"analysis for '{type1}': {len(findings_type1)} findings found "
                    f"but only first 10 will be analyzed. Results may be incomplete.",
                    file=sys.stderr,
                )
            if len(findings_type2) > 10:
                print(
                    f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Escalation path "
                    f"analysis for '{type2}': {len(findings_type2)} findings found "
                    f"but only first 10 will be analyzed. Results may be incomplete.",
                    file=sys.stderr,
                )
            for f1 in findings_type1[:10]:
                for f2 in findings_type2[:10]:
                    if f1.id == f2.id:
                        continue

                    # Same domain gets higher confidence
                    same_domain = (f1.domain == f2.domain)
                    related_domain = (
                        self._extract_parent_domain(f1.domain or "") ==
                        self._extract_parent_domain(f2.domain or "")
                    )

                    if same_domain:
                        confidence = 0.80
                    elif related_domain:
                        confidence = 0.65
                    else:
                        confidence = 0.45

                    # Boost for higher original severities
                    sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
                    combined_sev = sev_order.get(f1.severity, 1) + sev_order.get(f2.severity, 1)
                    if combined_sev >= 6:
                        confidence += 0.05

                    if confidence >= self.min_confidence:
                        description = (
                            f"{type1} + {type2} escalates to {escalated_sev}"
                        )
                        edge_id = self.graph.add_edge(
                            source_id=f1.id,
                            target_id=f2.id,
                            correlation_type=CORRELATION_TYPE_ESCALATION_PATH,
                            confidence=confidence,
                            description=description,
                            evidence=f"Escalation: {type1} + {type2} = {escalated_sev}",
                            rule_name="escalation_path",
                            severity_impact=escalated_sev,
                        )
                        if edge_id:
                            edges_created.append(self.graph.edges[edge_id])

        self.stats["correlation_types"]["ESCALATION_PATH"] = len(edges_created)
        return edges_created

    # =========================================================================
    # ANALYSIS ORCHESTRATION
    # =========================================================================

    def run_full_analysis(self) -> Dict[str, Any]:
        """
        Run all correlation detection algorithms.

        Executes each correlation type detector and aggregates results.

        Returns:
            Dictionary with analysis statistics and summary.
        """
        start_time = time.time()

        if not self.findings:
            return {"error": "No findings loaded", "total_correlations": 0}

        # Run each correlation type
        same_vuln_edges = self.detect_same_vuln_multi_target()
        attack_chains = self.detect_attack_chains()
        infra_edges = self.detect_shared_infrastructure()
        cookie_edges = self.detect_cookie_scope_attacks()
        tech_edges = self.detect_tech_stack_correlation()
        escalation_edges = self.detect_escalation_paths()

        # Store chains
        self.attack_chains = attack_chains

        # Collect all edges
        self.correlation_edges = (
            same_vuln_edges + infra_edges + cookie_edges +
            tech_edges + escalation_edges
        )

        # Generate composite findings for high-confidence chains
        self._generate_composite_findings()

        # Detect clusters
        self._detect_clusters()

        # Update stats
        self.stats["total_correlations"] = self.graph.edge_count()
        self.stats["total_chains"] = len(self.attack_chains)
        self.stats["total_escalated"] = len(self.escalated_findings)
        self.stats["processing_time"] = time.time() - start_time

        return {
            "total_findings_analyzed": len(self.findings),
            "total_correlations": self.graph.edge_count(),
            "total_attack_chains": len(self.attack_chains),
            "total_escalated": len(self.escalated_findings),
            "total_clusters": len(self.clusters),
            "correlation_breakdown": dict(self.stats["correlation_types"]),
            "processing_time_seconds": round(self.stats["processing_time"], 2),
            "graph_density": round(self.graph.density(), 4),
        }

    def _generate_composite_findings(self):
        """
        Generate composite findings from high-confidence attack chains.
        
        When a chain has confidence > 0.7, creates a new escalated
        composite finding in the database.
        """
        self.escalated_findings = []

        for chain in self.attack_chains:
            if chain.total_confidence < 0.7:
                continue

            # Create composite finding in DB if available
            if self.db and chain.finding_ids:
                composite_data = {
                    "chain_id": chain.id,
                    "title": f"[ESCALATED] {chain.title}",
                    "description": chain.description,
                    "escalated_severity": chain.escalated_severity,
                    "original_severity": chain.original_max_severity,
                    "confidence": chain.total_confidence,
                    "finding_ids": chain.finding_ids,
                    "domains": chain.domains,
                    "attack_vector": chain.attack_vector,
                    "impact": chain.impact,
                    "estimated_bounty": chain.estimated_bounty,
                }
                self.escalated_findings.append(composite_data)

                # Create in DB
                try:
                    self.db.create_composite_finding(
                        child_ids=chain.finding_ids[:10],
                        title=f"[CHAIN] {chain.title}",
                        description=chain.description,
                        severity=chain.escalated_severity,
                        chain_description=chain.description,
                    )
                except Exception:
                    pass

    def _detect_clusters(self):
        """Detect and label clusters from connected components."""
        self.clusters = []
        components = self.graph.find_connected_components()

        for idx, component in enumerate(components):
            if len(component) < 2:
                continue

            # Determine cluster properties
            domains = set()
            max_sev = "INFO"
            types_in_cluster = set()
            sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

            for node_id in component:
                node = self.graph.nodes.get(node_id)
                if node:
                    domains.add(node.domain)
                    types_in_cluster.add(node.finding_type)
                    if sev_order.get(node.severity, 0) > sev_order.get(max_sev, 0):
                        max_sev = node.severity

            # Determine correlation type for the cluster
            edges_in_cluster = []
            for node_id in component:
                edges_in_cluster.extend(self.graph.get_edges_for_node(node_id))

            type_counts: Dict[str, int] = defaultdict(int)
            for edge in edges_in_cluster:
                type_counts[edge.correlation_type] += 1

            primary_type = max(type_counts, key=type_counts.get) if type_counts else "MIXED"

            # Calculate average confidence
            confidences = [e.confidence for e in edges_in_cluster if e.confidence > 0]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

            cluster = CorrelationCluster(
                id=f"CLUSTER-{idx+1:03d}",
                name=f"{primary_type} cluster on {', '.join(list(domains)[:3])}",
                finding_ids=component,
                correlation_type=primary_type,
                confidence=round(avg_confidence, 3),
                domains=list(domains),
                max_severity=max_sev,
                description=f"Cluster of {len(component)} related findings across {len(domains)} domains",
            )
            self.clusters.append(cluster)

            # Store in graph
            self.graph.clusters[cluster.id] = cluster

    # =========================================================================
    # VISUALIZATION METHODS
    # =========================================================================

    def _generate_chain_ascii(self, steps: List[Dict[str, Any]]) -> str:
        """
        Generate ASCII visualization of an attack chain.

        Args:
            steps: List of step dictionaries with finding info.

        Returns:
            Multi-line ASCII art string showing the chain.
        """
        if not steps:
            return ""

        lines = []
        lines.append("")
        lines.append("  Attack Chain Visualization")
        lines.append("  " + "=" * 60)

        for i, step in enumerate(steps):
            step_num = step.get("step_number", i + 1)
            finding_type = step.get("finding_type", "unknown")
            severity = step.get("severity", "INFO")
            domain = step.get("domain", "unknown")
            title = step.get("title", "")[:40]

            # Node representation
            sev_indicator = {"CRITICAL": "!!", "HIGH": "! ", "MEDIUM": "* ", "LOW": ". ", "INFO": "  "}.get(severity, "  ")
            node_line = f"  [{sev_indicator}] Step {step_num}: {finding_type}"
            lines.append(node_line)
            lines.append(f"       Domain: {domain}")
            if title:
                lines.append(f"       Detail: {title}")

            # Arrow to next step
            if i < len(steps) - 1:
                lines.append("       |")
                lines.append("       | exploits")
                lines.append("       v")

        lines.append("  " + "=" * 60)
        lines.append(f"  Result: Severity escalated to {steps[-1].get('severity', 'HIGH') if steps else 'HIGH'}")
        lines.append("")

        return "\n".join(lines)

    def generate_full_ascii_graph(self, max_nodes: int = 20) -> str:
        """
        Generate a full ASCII representation of the correlation graph.

        Args:
            max_nodes: Maximum number of nodes to display.

        Returns:
            Multi-line ASCII string showing the graph structure.
        """
        lines = []
        lines.append("")
        lines.append("  Correlation Graph Overview")
        lines.append("  " + "=" * 70)
        lines.append(f"  Nodes: {self.graph.node_count()} | Edges: {self.graph.edge_count()} | "
                     f"Density: {self.graph.density():.4f}")
        lines.append("")

        # Show connected components
        components = self.graph.find_connected_components()
        if components:
            lines.append(f"  Connected Components: {len(components)}")
            for idx, component in enumerate(components[:5]):
                lines.append(f"    Component {idx+1}: {len(component)} nodes")
                for node_id in component[:5]:
                    node = self.graph.nodes.get(node_id)
                    if node:
                        sev_mark = {"CRITICAL": "[!!]", "HIGH": "[! ]", "MEDIUM": "[* ]", "LOW": "[. ]", "INFO": "[  ]"}.get(node.severity, "[  ]")
                        lines.append(f"      {sev_mark} {node.finding_type} @ {node.domain}")
                if len(component) > 5:
                    lines.append(f"      ... +{len(component)-5} more nodes")
            lines.append("")

        # Show high centrality nodes
        high_central = self.graph.get_high_centrality_nodes(5)
        if high_central:
            lines.append("  Most Connected Findings:")
            for node_id, centrality in high_central:
                node = self.graph.nodes.get(node_id)
                if node:
                    edges = len(self.graph.adjacency.get(node_id, []))
                    lines.append(f"    [{centrality:.2f}] {node.finding_type} @ {node.domain} ({edges} connections)")
            lines.append("")

        # Show edge type distribution
        type_counts: Dict[str, int] = defaultdict(int)
        for edge in self.graph.edges.values():
            type_counts[edge.correlation_type] += 1

        if type_counts:
            lines.append("  Correlation Type Distribution:")
            for ctype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                bar_len = min(count, 40)
                bar = "#" * bar_len
                lines.append(f"    {ctype:<30} [{bar}] {count}")
            lines.append("")

        lines.append("  " + "=" * 70)
        return "\n".join(lines)

    def generate_chain_visualization(self, chain: AttackChain) -> str:
        """Generate detailed ASCII visualization for a specific chain."""
        lines = []
        lines.append("")
        lines.append(f"  Chain: {chain.title}")
        lines.append(f"  Confidence: {chain.total_confidence:.2f} | "
                     f"Escalated: {chain.escalated_severity}")
        lines.append("  " + "-" * 60)

        for i, step in enumerate(chain.steps):
            prefix = "  START" if i == 0 else "       "
            suffix = "  END" if i == len(chain.steps) - 1 else ""
            
            sev = step.get("severity", "INFO")
            finding_type = step.get("finding_type", "?")
            domain = step.get("domain", "?")

            lines.append(f"  +{'=' * 50}+")
            lines.append(f"  | Step {i+1}: {finding_type:<20} [{sev:<8}]     |")
            lines.append(f"  | Domain: {domain:<40} |")
            lines.append(f"  +{'=' * 50}+")

            if i < len(chain.steps) - 1:
                lines.append("            |")
                lines.append("            | leads to")
                lines.append("            v")

        lines.append("")
        lines.append(f"  Impact: {chain.impact}")
        lines.append(f"  Est. Bounty: ${chain.estimated_bounty:,.0f}")
        lines.append("")

        return "\n".join(lines)

    # =========================================================================
    # OUTPUT GENERATION
    # =========================================================================

    def generate_report(self, output_dir: str = None) -> Dict[str, str]:
        """
        Generate all output files: correlation_report.json, attack_chains.md,
        and escalated_findings.json.

        Args:
            output_dir: Output directory path. Uses self.output_dir if None.

        Returns:
            Dictionary mapping output type to file path.
        """
        output_dir = output_dir or self.output_dir
        os.makedirs(output_dir, exist_ok=True)
        output_files = {}

        # 1. correlation_report.json
        report_path = os.path.join(output_dir, "correlation_report.json")
        report_data = self._build_correlation_report()
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)
        output_files["correlation_report"] = report_path

        # 2. attack_chains.md
        chains_path = os.path.join(output_dir, "attack_chains.md")
        chains_md = self._build_chains_markdown()
        with open(chains_path, "w", encoding="utf-8") as f:
            f.write(chains_md)
        output_files["attack_chains"] = chains_path

        # 3. escalated_findings.json
        escalated_path = os.path.join(output_dir, "escalated_findings.json")
        escalated_data = {
            "escalated_findings_report": {
                "generated_at": datetime.utcnow().isoformat(),
                "generator": TOOL_BANNER,
                "total_escalated": len(self.escalated_findings),
                "min_confidence": self.min_confidence,
            },
            "escalated_findings": self.escalated_findings,
        }
        with open(escalated_path, "w", encoding="utf-8") as f:
            json.dump(escalated_data, f, indent=2, default=str)
        output_files["escalated_findings"] = escalated_path

        return output_files

    def _build_correlation_report(self) -> Dict[str, Any]:
        """Build the full correlation report data structure."""
        return {
            "correlation_report": {
                "report_id": f"CORR-RPT-{uuid.uuid4().hex[:8].upper()}",
                "generated_at": datetime.utcnow().isoformat(),
                "generator": TOOL_BANNER,
                "total_findings_analyzed": len(self.findings),
                "total_correlations_found": self.graph.edge_count(),
                "total_attack_chains": len(self.attack_chains),
                "total_escalated_findings": len(self.escalated_findings),
                "total_clusters": len(self.clusters),
                "min_confidence_threshold": self.min_confidence,
                "graph_statistics": {
                    "nodes": self.graph.node_count(),
                    "edges": self.graph.edge_count(),
                    "density": round(self.graph.density(), 4),
                    "connected_components": len(self.graph.find_connected_components()),
                },
            },
            "correlation_summary": {
                "by_type": dict(self.stats["correlation_types"]),
                "high_confidence_count": sum(
                    1 for e in self.graph.edges.values() if e.confidence >= 0.8
                ),
                "medium_confidence_count": sum(
                    1 for e in self.graph.edges.values() if 0.6 <= e.confidence < 0.8
                ),
                "domains_involved": list(set(
                    n.domain for n in self.graph.nodes.values() if n.domain
                )),
            },
            "attack_chains": [chain.to_dict() for chain in self.attack_chains],
            "clusters": [cluster.to_dict() for cluster in self.clusters],
            "edges": [edge.to_dict() for edge in list(self.graph.edges.values())[:100]],
            "escalated_findings": self.escalated_findings,
        }

    def _build_chains_markdown(self) -> str:
        """Build the attack chains Markdown report."""
        lines = []
        lines.append("# Attack Chains Report")
        lines.append("")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}")
        lines.append(f"Generator: {TOOL_BANNER}")
        lines.append(f"Total Chains: {len(self.attack_chains)}")
        lines.append("")
        lines.append("---")
        lines.append("")

        if not self.attack_chains:
            lines.append("No attack chains detected.")
            lines.append("")
            lines.append("This may indicate:")
            lines.append("- Findings are isolated (not related)")
            lines.append("- Confidence threshold is too high")
            lines.append("- More findings needed for chain detection")
            return "\n".join(lines)

        # Sort chains by confidence
        sorted_chains = sorted(self.attack_chains, key=lambda c: c.total_confidence, reverse=True)

        for idx, chain in enumerate(sorted_chains, 1):
            lines.append(f"## Chain {idx}: {chain.title}")
            lines.append("")
            lines.append(f"- **Confidence:** {chain.total_confidence:.2f}")
            lines.append(f"- **Escalated Severity:** {chain.escalated_severity}")
            lines.append(f"- **Original Max Severity:** {chain.original_max_severity}")
            lines.append(f"- **Domains:** {', '.join(chain.domains)}")
            lines.append(f"- **Attack Vector:** {chain.attack_vector}")
            lines.append(f"- **Estimated Bounty:** ${chain.estimated_bounty:,.0f}")
            lines.append("")
            lines.append("### Impact")
            lines.append("")
            lines.append(chain.impact)
            lines.append("")
            lines.append("### Steps")
            lines.append("")

            for step in chain.steps:
                step_num = step.get("step_number", "?")
                finding_type = step.get("finding_type", "unknown")
                severity = step.get("severity", "INFO")
                domain = step.get("domain", "unknown")
                lines.append(f"{step_num}. **{finding_type}** [{severity}] on `{domain}`")

            lines.append("")
            if chain.prerequisites:
                lines.append("### Prerequisites")
                lines.append("")
                for prereq in chain.prerequisites:
                    lines.append(f"- {prereq}")
                lines.append("")

            if chain.visualization:
                lines.append("### Visualization")
                lines.append("")
                lines.append("```")
                lines.append(chain.visualization)
                lines.append("```")
                lines.append("")

            lines.append("---")
            lines.append("")

        # Summary table
        lines.append("## Summary")
        lines.append("")
        lines.append("| # | Chain | Confidence | Severity | Domains | Bounty |")
        lines.append("|---|-------|-----------|----------|---------|--------|")
        for idx, chain in enumerate(sorted_chains[:20], 1):
            title_short = chain.title[:30]
            domains_short = ", ".join(chain.domains[:2])
            lines.append(
                f"| {idx} | {title_short} | {chain.total_confidence:.2f} | "
                f"{chain.escalated_severity} | {domains_short} | ${chain.estimated_bounty:,.0f} |"
            )
        lines.append("")

        return "\n".join(lines)

    # =========================================================================
    # TERMINAL OUTPUT
    # =========================================================================

    def print_summary(self):
        """Print a colored summary of correlation results to terminal."""
        print(f"\n{Colors.HEADER}{'=' * 70}")
        print(f"  CORRELATION ANALYSIS RESULTS")
        print(f"{'=' * 70}{Colors.RESET}")
        print(f"  {Colors.LABEL}Findings Analyzed:{Colors.RESET}  {self.stats['total_findings']}")
        print(f"  {Colors.LABEL}Correlations Found:{Colors.RESET} {self.graph.edge_count()}")
        print(f"  {Colors.LABEL}Attack Chains:{Colors.RESET}      {len(self.attack_chains)}")
        print(f"  {Colors.LABEL}Escalated:{Colors.RESET}          {len(self.escalated_findings)}")
        print(f"  {Colors.LABEL}Clusters:{Colors.RESET}           {len(self.clusters)}")
        print(f"  {Colors.LABEL}Graph Density:{Colors.RESET}      {self.graph.density():.4f}")
        print(f"  {Colors.LABEL}Processing Time:{Colors.RESET}    {self.stats['processing_time']:.2f}s")
        print()

        # Correlation type breakdown
        if self.stats["correlation_types"]:
            print(f"  {Colors.SUBHEADER}Correlation Types:{Colors.RESET}")
            for ctype, count in sorted(self.stats["correlation_types"].items(), key=lambda x: x[1], reverse=True):
                bar = "#" * min(count, 30)
                print(f"    {ctype:<30} {Colors.PROGRESS_BAR}{bar}{Colors.RESET} {count}")
            print()

        # Top chains
        if self.attack_chains:
            print(f"  {Colors.SUBHEADER}Top Attack Chains:{Colors.RESET}")
            sorted_chains = sorted(self.attack_chains, key=lambda c: c.total_confidence, reverse=True)
            for chain in sorted_chains[:5]:
                sev_color = Colors.severity_color(chain.escalated_severity)
                print(f"    {sev_color}{chain.escalated_severity:<8}{Colors.RESET} "
                      f"[{chain.total_confidence:.2f}] {chain.title[:50]}")
                print(f"             Domains: {', '.join(chain.domains[:3])}")
                print(f"             Bounty: ${chain.estimated_bounty:,.0f}")
            print()

        # Escalated findings
        if self.escalated_findings:
            print(f"  {Colors.SUBHEADER}Escalated Findings (confidence > 0.7):{Colors.RESET}")
            for esc in self.escalated_findings[:5]:
                sev_color = Colors.severity_color(esc["escalated_severity"])
                print(f"    {sev_color}{esc['escalated_severity']:<8}{Colors.RESET} "
                      f"{esc['title'][:55]}")
            print()

        print(f"{Colors.HEADER}{'=' * 70}{Colors.RESET}\n")

    def print_chains_detail(self, limit: int = 10):
        """Print detailed attack chain information with ASCII visualization."""
        if not self.attack_chains:
            print(f"  {Colors.WARNING}No attack chains detected.{Colors.RESET}")
            return

        sorted_chains = sorted(self.attack_chains, key=lambda c: c.total_confidence, reverse=True)

        for chain in sorted_chains[:limit]:
            print(self.generate_chain_visualization(chain))

    def get_analysis_stats(self) -> Dict[str, Any]:
        """Get comprehensive analysis statistics."""
        return {
            "total_findings": len(self.findings),
            "total_correlations": self.graph.edge_count(),
            "total_chains": len(self.attack_chains),
            "total_escalated": len(self.escalated_findings),
            "total_clusters": len(self.clusters),
            "graph_nodes": self.graph.node_count(),
            "graph_edges": self.graph.edge_count(),
            "graph_density": self.graph.density(),
            "correlation_types": dict(self.stats["correlation_types"]),
            "processing_time": self.stats["processing_time"],
            "rule_stats": self.rule_engine.get_rule_statistics(),
        }


# =============================================================================
# ADVANCED ANALYSIS METHODS
# =============================================================================

class AdvancedCorrelator:
    """
    Advanced correlation methods that extend the base CorrelationEngine
    with more sophisticated analysis capabilities.
    
    Includes:
    - Cross-domain pivot analysis
    - Authentication chain detection
    - Data flow tracking
    - Temporal correlation (findings discovered close in time)
    - Severity escalation scoring
    - Attack surface mapping
    """

    def __init__(self, engine: CorrelationEngine):
        """
        Initialize advanced correlator with a base engine.

        Args:
            engine: The CorrelationEngine instance to extend.
        """
        self.engine = engine
        self.graph = engine.graph
        self.findings = engine.findings
        self._pivot_chains: List[Dict[str, Any]] = []
        self._auth_chains: List[Dict[str, Any]] = []
        self._data_flows: List[Dict[str, Any]] = []

    def analyze_cross_domain_pivots(self) -> List[Dict[str, Any]]:
        """
        Analyze potential cross-domain pivot paths.
        
        Identifies how compromising one domain could lead to access
        on another domain through shared sessions, tokens, or APIs.

        Returns:
            List of pivot chain descriptions.
        """
        pivots = []
        
        # Group findings by parent domain
        parent_groups: Dict[str, List[Finding]] = defaultdict(list)
        for f in self.findings:
            parent = self._get_parent_domain(f.domain or "")
            parent_groups[parent].append(f)

        # Find cross-subdomain attack paths
        for parent_domain, domain_findings in parent_groups.items():
            if len(domain_findings) < 2:
                continue

            # Group by subdomain
            subdomain_groups: Dict[str, List[Finding]] = defaultdict(list)
            for f in domain_findings:
                subdomain_groups[f.domain or "unknown"].append(f)

            if len(subdomain_groups) < 2:
                continue

            # Look for pivot opportunities
            subdomains = list(subdomain_groups.keys())
            for i in range(len(subdomains)):
                for j in range(i + 1, len(subdomains)):
                    sd1 = subdomains[i]
                    sd2 = subdomains[j]
                    f1_list = subdomain_groups[sd1]
                    f2_list = subdomain_groups[sd2]

                    pivot = self._check_pivot_opportunity(sd1, f1_list, sd2, f2_list)
                    if pivot:
                        pivots.append(pivot)

        self._pivot_chains = pivots
        return pivots

    def _check_pivot_opportunity(self, domain1: str, findings1: List[Finding],
                                  domain2: str, findings2: List[Finding]) -> Optional[Dict[str, Any]]:
        """Check if findings on two domains create a pivot opportunity."""
        pivot_indicators = {
            "cors": "CORS allows cross-origin requests",
            "cookie_flags": "Cookies accessible across subdomains",
            "session_fixation": "Session can be fixed from another subdomain",
            "open_redirect": "Can redirect users to attacker subdomain",
            "subdomain_takeover": "Subdomain can be claimed for attacks",
            "xss_stored": "XSS can steal tokens from shared origin",
        }

        f1_types = set(f.finding_type for f in findings1)
        f2_types = set(f.finding_type for f in findings2)

        pivot_types_found = []
        for ptype in pivot_indicators:
            if ptype in f1_types or ptype in f2_types:
                pivot_types_found.append(ptype)

        if len(pivot_types_found) >= 2:
            return {
                "source_domain": domain1,
                "target_domain": domain2,
                "pivot_types": pivot_types_found,
                "confidence": min(0.5 + len(pivot_types_found) * 0.1, 0.9),
                "description": f"Pivot from {domain1} to {domain2} via {', '.join(pivot_types_found)}",
                "indicators": [pivot_indicators[pt] for pt in pivot_types_found],
                "source_findings": [f.id for f in findings1 if f.finding_type in pivot_types_found],
                "target_findings": [f.id for f in findings2 if f.finding_type in pivot_types_found],
            }
        return None

    def _get_parent_domain(self, domain: str) -> str:
        """Extract parent domain."""
        parts = domain.lower().strip().split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain

    def analyze_auth_chains(self) -> List[Dict[str, Any]]:
        """
        Detect authentication-related attack chains.
        
        Identifies combinations of findings that could lead to
        account takeover or authentication bypass.

        Returns:
            List of authentication chain descriptions.
        """
        auth_chains = []

        auth_types = [
            "auth_bypass", "credential_exposure", "session_fixation",
            "session_hijack", "cookie_theft", "csrf", "jwt_vulnerability",
            "default_credentials", "weak_password", "xss_stored",
        ]

        auth_findings = []
        for atype in auth_types:
            auth_findings.extend(self.engine._type_map.get(atype, []))

        if len(auth_findings) < 2:
            return auth_chains

        # Group by domain
        domain_auth: Dict[str, List[Finding]] = defaultdict(list)
        for f in auth_findings:
            domain_auth[f.domain or "unknown"].append(f)

        for domain, findings in domain_auth.items():
            if len(findings) < 2:
                continue

            types_present = set(f.finding_type for f in findings)

            # Check for known auth chain patterns
            chain = None
            if "credential_exposure" in types_present and any(
                t in types_present for t in ["auth_bypass", "idor", "session_hijack"]
            ):
                chain = {
                    "domain": domain,
                    "chain_type": "credential_to_access",
                    "severity": "CRITICAL",
                    "description": f"Leaked credentials enable unauthorized access on {domain}",
                    "finding_types": list(types_present),
                    "finding_ids": [f.id for f in findings],
                    "confidence": 0.85,
                }
            elif "xss_stored" in types_present and "session_hijack" in types_present:
                chain = {
                    "domain": domain,
                    "chain_type": "xss_to_takeover",
                    "severity": "CRITICAL",
                    "description": f"Stored XSS enables account takeover via session theft on {domain}",
                    "finding_types": list(types_present),
                    "finding_ids": [f.id for f in findings],
                    "confidence": 0.80,
                }
            elif "csrf" in types_present and any(
                t in types_present for t in ["session_fixation", "xss_reflected"]
            ):
                chain = {
                    "domain": domain,
                    "chain_type": "csrf_chain",
                    "severity": "HIGH",
                    "description": f"CSRF combined with session issues on {domain}",
                    "finding_types": list(types_present),
                    "finding_ids": [f.id for f in findings],
                    "confidence": 0.70,
                }
            elif "jwt_vulnerability" in types_present:
                chain = {
                    "domain": domain,
                    "chain_type": "jwt_bypass",
                    "severity": "HIGH",
                    "description": f"JWT vulnerability enables auth bypass on {domain}",
                    "finding_types": list(types_present),
                    "finding_ids": [f.id for f in findings],
                    "confidence": 0.75,
                }
            elif len(types_present) >= 3:
                chain = {
                    "domain": domain,
                    "chain_type": "complex_auth_chain",
                    "severity": "HIGH",
                    "description": f"Multiple auth weaknesses on {domain}: {', '.join(types_present)}",
                    "finding_types": list(types_present),
                    "finding_ids": [f.id for f in findings],
                    "confidence": 0.65,
                }

            if chain:
                auth_chains.append(chain)

        self._auth_chains = auth_chains
        return auth_chains

    def analyze_data_flows(self) -> List[Dict[str, Any]]:
        """
        Track potential data exfiltration paths.
        
        Maps how data could flow from internal/sensitive endpoints
        to external-facing ones through identified vulnerabilities.

        Returns:
            List of data flow path descriptions.
        """
        data_flows = []

        # Data source findings (where sensitive data exists)
        source_types = ["sqli", "idor", "pii_leak", "data_exposure",
                       "credential_exposure", "api_key_leak", "info_disclosure"]
        # Data sink findings (how data can be extracted)
        sink_types = ["ssrf", "cors", "open_redirect", "xss_stored",
                     "file_upload", "xxe"]

        sources = []
        for stype in source_types:
            sources.extend(self.engine._type_map.get(stype, []))

        sinks = []
        for stype in sink_types:
            sinks.extend(self.engine._type_map.get(stype, []))

        if not sources or not sinks:
            return data_flows

        # Match sources to sinks on same/related domains
        for source in sources[:20]:
            source_parent = self._get_parent_domain(source.domain or "")
            for sink in sinks[:20]:
                sink_parent = self._get_parent_domain(sink.domain or "")

                if source_parent == sink_parent or source.domain == sink.domain:
                    confidence = 0.60
                    if source.domain == sink.domain:
                        confidence += 0.15
                    if source.cvss_score >= 7.0:
                        confidence += 0.05
                    if sink.cvss_score >= 5.0:
                        confidence += 0.05

                    flow = {
                        "source_finding": source.id,
                        "source_type": source.finding_type,
                        "source_domain": source.domain,
                        "sink_finding": sink.id,
                        "sink_type": sink.finding_type,
                        "sink_domain": sink.domain,
                        "confidence": min(confidence, 0.95),
                        "description": (
                            f"Data from {source.finding_type} on {source.domain} "
                            f"extractable via {sink.finding_type} on {sink.domain}"
                        ),
                        "severity": "HIGH" if confidence >= 0.75 else "MEDIUM",
                    }
                    data_flows.append(flow)

        # Sort by confidence
        data_flows.sort(key=lambda f: f["confidence"], reverse=True)
        self._data_flows = data_flows[:50]
        return self._data_flows

    def analyze_temporal_correlation(self) -> List[Dict[str, Any]]:
        """
        Detect temporal correlations between findings.
        
        Findings discovered close in time from the same scan may
        share a root cause or common exploitation vector.

        Returns:
            List of temporal correlation groups.
        """
        temporal_groups = []

        # Sort findings by discovery time
        timed_findings = [
            f for f in self.findings if f.discovered_at
        ]
        timed_findings.sort(key=lambda f: f.discovered_at)

        if len(timed_findings) < 2:
            return temporal_groups

        # Group findings within 5-minute windows
        window_seconds = 300
        current_group: List[Finding] = [timed_findings[0]]

        for i in range(1, len(timed_findings)):
            try:
                prev_time = datetime.fromisoformat(timed_findings[i-1].discovered_at)
                curr_time = datetime.fromisoformat(timed_findings[i].discovered_at)
                diff = (curr_time - prev_time).total_seconds()

                if diff <= window_seconds:
                    current_group.append(timed_findings[i])
                else:
                    if len(current_group) >= 3:
                        temporal_groups.append(self._build_temporal_group(current_group))
                    current_group = [timed_findings[i]]
            except (ValueError, TypeError):
                if len(current_group) >= 3:
                    temporal_groups.append(self._build_temporal_group(current_group))
                current_group = [timed_findings[i]]

        if len(current_group) >= 3:
            temporal_groups.append(self._build_temporal_group(current_group))

        return temporal_groups

    def _build_temporal_group(self, findings: List[Finding]) -> Dict[str, Any]:
        """Build a temporal correlation group from clustered findings."""
        domains = list(set(f.domain for f in findings if f.domain))
        types = list(set(f.finding_type for f in findings))
        severities = [f.severity for f in findings]
        sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        max_sev = max(severities, key=lambda s: sev_order.get(s, 0))

        return {
            "finding_count": len(findings),
            "finding_ids": [f.id for f in findings],
            "domains": domains,
            "finding_types": types,
            "max_severity": max_sev,
            "time_range": {
                "start": findings[0].discovered_at,
                "end": findings[-1].discovered_at,
            },
            "description": (
                f"{len(findings)} findings discovered in same time window "
                f"across {len(domains)} domains"
            ),
            "possible_root_cause": self._guess_root_cause(types),
        }

    def _guess_root_cause(self, types: List[str]) -> str:
        """Guess potential root cause from finding types."""
        if "missing_headers" in types and "cookie_flags" in types:
            return "Server misconfiguration (missing security headers)"
        if "cors" in types:
            return "CORS misconfiguration (likely server-wide)"
        if any(t in types for t in ["sqli", "xss_stored", "xss_reflected"]):
            return "Input validation failure (no proper sanitization)"
        if "info_disclosure" in types and "version_disclosure" in types:
            return "Default/debug configuration exposed"
        if "subdomain_takeover" in types:
            return "Orphaned DNS records pointing to deprovisioned services"
        return "Multiple vulnerabilities from same scan module"

    def calculate_attack_surface_score(self) -> Dict[str, Any]:
        """
        Calculate overall attack surface score from correlations.

        Returns:
            Dictionary with attack surface metrics and score.
        """
        total_findings = len(self.findings)
        unique_domains = len(set(f.domain for f in self.findings if f.domain))
        unique_types = len(set(f.finding_type for f in self.findings))
        critical_count = sum(1 for f in self.findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in self.findings if f.severity == "HIGH")
        chain_count = len(self.engine.attack_chains)

        # Weighted score calculation
        score = 0.0
        score += min(total_findings / 100.0, 1.0) * 20  # Volume
        score += min(unique_domains / 20.0, 1.0) * 15  # Breadth
        score += min(unique_types / 15.0, 1.0) * 15  # Diversity
        score += min(critical_count / 5.0, 1.0) * 25  # Critical severity
        score += min(high_count / 10.0, 1.0) * 15  # High severity
        score += min(chain_count / 5.0, 1.0) * 10  # Chain complexity

        # Determine risk level
        if score >= 80:
            risk_level = "EXTREME"
        elif score >= 60:
            risk_level = "HIGH"
        elif score >= 40:
            risk_level = "MEDIUM"
        elif score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        return {
            "attack_surface_score": round(score, 1),
            "risk_level": risk_level,
            "metrics": {
                "total_findings": total_findings,
                "unique_domains": unique_domains,
                "unique_finding_types": unique_types,
                "critical_findings": critical_count,
                "high_findings": high_count,
                "attack_chains": chain_count,
                "correlations": self.engine.graph.edge_count(),
            },
            "breakdown": {
                "volume_score": round(min(total_findings / 100.0, 1.0) * 20, 1),
                "breadth_score": round(min(unique_domains / 20.0, 1.0) * 15, 1),
                "diversity_score": round(min(unique_types / 15.0, 1.0) * 15, 1),
                "severity_score": round(min(critical_count / 5.0, 1.0) * 25, 1),
                "chain_score": round(min(chain_count / 5.0, 1.0) * 10, 1),
            },
        }


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def correlate_findings(input_path: str, output_dir: str = None,
                       db_path: str = None, min_confidence: float = 0.6) -> Dict[str, Any]:
    """
    High-level utility function to correlate findings from a path.

    This is the main entry point called by the CLI subcommand.

    Args:
        input_path: Path to Monster JSON reports (file or directory).
        output_dir: Output directory for results.
        db_path: Path to findings database file.
        min_confidence: Minimum confidence threshold.

    Returns:
        Dictionary with analysis results and output file paths.
    """
    # Initialize database
    db = FindingDB(db_path) if db_path else FindingDB()

    # Import findings
    if input_path:
        if os.path.isdir(input_path):
            db.import_directory(input_path)
        elif os.path.isfile(input_path):
            db.import_monster_report(input_path)

    if db.count() == 0:
        return {"error": "No findings to correlate", "total_correlations": 0}

    # Create and run engine
    engine = CorrelationEngine(
        db=db,
        min_confidence=min_confidence,
        output_dir=output_dir or DEFAULT_OUTPUT_DIR,
    )
    engine.load_findings_from_db()

    # Run full analysis
    results = engine.run_full_analysis()

    # Run advanced analysis
    advanced = AdvancedCorrelator(engine)
    pivot_results = advanced.analyze_cross_domain_pivots()
    auth_chains = advanced.analyze_auth_chains()
    data_flows = advanced.analyze_data_flows()
    attack_surface = advanced.calculate_attack_surface_score()

    # Generate output files
    output_files = engine.generate_report(output_dir)

    # Print summary
    engine.print_summary()

    # Save database
    if db_path and db.db_path:
        db.save()

    return {
        "analysis_results": results,
        "output_files": output_files,
        "pivot_chains": len(pivot_results),
        "auth_chains": len(auth_chains),
        "data_flows": len(data_flows),
        "attack_surface": attack_surface,
    }


def quick_correlate(findings: List[Dict[str, Any]], min_confidence: float = 0.6) -> Dict[str, Any]:
    """
    Quick correlation analysis from a list of finding dictionaries.

    Useful for programmatic access without file I/O.

    Args:
        findings: List of finding dictionaries.
        min_confidence: Minimum confidence threshold.

    Returns:
        Correlation analysis results.
    """
    db = FindingDB()
    for f_dict in findings:
        finding = Finding.from_dict(f_dict)
        if not finding.id:
            finding.id = f"QC-{uuid.uuid4().hex[:8].upper()}"
        finding.compute_fingerprint()
        db.add_finding(finding, deduplicate=True)

    engine = CorrelationEngine(db=db, min_confidence=min_confidence)
    engine.load_findings_from_db()
    results = engine.run_full_analysis()

    return {
        "results": results,
        "chains": [c.to_dict() for c in engine.attack_chains],
        "escalated": engine.escalated_findings,
        "clusters": [c.to_dict() for c in engine.clusters],
    }


def get_correlation_summary(db: FindingDB, min_confidence: float = 0.6) -> str:
    """
    Get a brief text summary of correlations for a FindingDB.

    Args:
        db: The FindingDB to analyze.
        min_confidence: Minimum confidence threshold.

    Returns:
        Multi-line text summary string.
    """
    engine = CorrelationEngine(db=db, min_confidence=min_confidence)
    engine.load_findings_from_db()
    results = engine.run_full_analysis()

    lines = []
    lines.append(f"Correlation Summary ({db.count()} findings)")
    lines.append(f"  Correlations: {results.get('total_correlations', 0)}")
    lines.append(f"  Attack Chains: {results.get('total_attack_chains', 0)}")
    lines.append(f"  Escalated: {results.get('total_escalated', 0)}")
    lines.append(f"  Clusters: {results.get('total_clusters', 0)}")

    if engine.attack_chains:
        lines.append(f"  Top Chain: {engine.attack_chains[0].title}")

    return "\n".join(lines)
