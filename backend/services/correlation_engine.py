"""
Finding Correlation Engine

Links related security findings into attack chains and identifies
multi-step attack paths with business impact assessment.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum
from datetime import datetime


class ImpactLevel(Enum):
    """Business impact levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingType(Enum):
    """Types of security findings."""
    INJECTION = "injection"
    AUTH_BYPASS = "auth_bypass"
    ACCESS_CONTROL = "access_control"
    INFO_DISCLOSURE = "info_disclosure"
    CSRF = "csrf"
    XSS = "xss"
    CONFIGURATION = "configuration"
    CRYPTO = "crypto"
    LOGIC_FLAW = "logic_flaw"
    FILE_UPLOAD = "file_upload"
    OTHER = "other"


@dataclass
class Finding:
    """Represents a security finding."""
    
    id: str
    title: str
    finding_type: FindingType
    severity: str  # 'critical', 'high', 'medium', 'low'
    description: str
    affected_url: str
    timestamp: datetime = field(default_factory=lambda: datetime.now())
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackChain:
    """Represents a linked sequence of findings forming an attack path."""
    
    id: str
    name: str
    findings: List[Finding]
    steps: List[str]
    impact: ImpactLevel
    severity: str
    confidence: float  # 0.0 to 1.0
    business_impact: str
    technical_impact: str
    exploitation_complexity: str  # 'low', 'medium', 'high'
    prerequisites: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)


@dataclass
class CorrelationResult:
    """Result of finding correlation analysis."""
    
    attack_chains: List[AttackChain] = field(default_factory=list)
    standalone_findings: List[Finding] = field(default_factory=list)
    finding_relationships: Dict[str, List[str]] = field(default_factory=dict)
    risk_score: float = 0.0


class CorrelationEngine:
    """
    Correlates security findings into attack chains.
    
    Identifies relationships between findings to form multi-step
    attack paths and assesses business impact.
    """
    
    # Finding type relationships (what can lead to what)
    ATTACK_RELATIONSHIPS = {
        FindingType.INFO_DISCLOSURE: {
            FindingType.INJECTION,
            FindingType.AUTH_BYPASS,
            FindingType.ACCESS_CONTROL,
        },
        FindingType.CSRF: {
            FindingType.ACCESS_CONTROL,
            FindingType.LOGIC_FLAW,
        },
        FindingType.XSS: {
            FindingType.AUTH_BYPASS,
            FindingType.CSRF,
        },
        FindingType.AUTH_BYPASS: {
            FindingType.ACCESS_CONTROL,
            FindingType.INJECTION,
        },
        FindingType.FILE_UPLOAD: {
            FindingType.INJECTION,
        },
    }
    
    # Known attack chain patterns
    ATTACK_PATTERNS = [
        {
            'name': 'Information Disclosure to Account Takeover',
            'pattern': [FindingType.INFO_DISCLOSURE, FindingType.AUTH_BYPASS],
            'impact': ImpactLevel.CRITICAL,
            'business_impact': 'Complete account compromise using leaked credentials or session tokens',
            'technical_impact': 'Unauthorized access to user accounts',
        },
        {
            'name': 'XSS to Session Hijacking',
            'pattern': [FindingType.XSS, FindingType.AUTH_BYPASS],
            'impact': ImpactLevel.HIGH,
            'business_impact': 'Account takeover via stolen session cookies',
            'technical_impact': 'JavaScript execution leading to credential theft',
        },
        {
            'name': 'CSRF to Privilege Escalation',
            'pattern': [FindingType.CSRF, FindingType.ACCESS_CONTROL],
            'impact': ImpactLevel.HIGH,
            'business_impact': 'Unauthorized actions performed with elevated privileges',
            'technical_impact': 'State-changing operations executed without user consent',
        },
        {
            'name': 'Info Leak to SQL Injection',
            'pattern': [FindingType.INFO_DISCLOSURE, FindingType.INJECTION],
            'impact': ImpactLevel.CRITICAL,
            'business_impact': 'Database breach using leaked technical details',
            'technical_impact': 'Full database compromise via injection attack',
        },
        {
            'name': 'File Upload to Code Execution',
            'pattern': [FindingType.FILE_UPLOAD, FindingType.INJECTION],
            'impact': ImpactLevel.CRITICAL,
            'business_impact': 'Server compromise through malicious file upload',
            'technical_impact': 'Remote code execution on server',
        },
    ]
    
    def __init__(self):
        """Initialize correlation engine."""
        self.findings_db: List[Finding] = []
        self.chain_counter = 0
    
    def add_finding(self, finding: Finding) -> None:
        """
        Add finding to correlation database.
        
        Args:
            finding: Security finding to add
        """
        self.findings_db.append(finding)
    
    def correlate(self, findings: Optional[List[Finding]] = None) -> CorrelationResult:
        """
        Correlate findings into attack chains.
        
        Args:
            findings: List of findings to correlate (or use internal DB)
            
        Returns:
            CorrelationResult with attack chains and relationships
        """
        if findings is None:
            findings = self.findings_db
        
        result = CorrelationResult()
        
        # Build finding relationships graph
        relationships = self._build_relationship_graph(findings)
        result.finding_relationships = relationships
        
        # Detect known attack patterns
        chains = self._detect_attack_patterns(findings)
        result.attack_chains.extend(chains)
        
        # Find custom multi-step chains
        custom_chains = self._find_custom_chains(findings, relationships)
        result.attack_chains.extend(custom_chains)
        
        # Identify standalone findings
        chained_finding_ids = set()
        for chain in result.attack_chains:
            chained_finding_ids.update(f.id for f in chain.findings)
        
        result.standalone_findings = [
            f for f in findings if f.id not in chained_finding_ids
        ]
        
        # Calculate overall risk score
        result.risk_score = self._calculate_risk_score(result)
        
        # Sort chains by severity
        result.attack_chains.sort(
            key=lambda c: (
                ['critical', 'high', 'medium', 'low'].index(c.severity),
                -c.confidence
            )
        )
        
        return result
    
    def _build_relationship_graph(
        self,
        findings: List[Finding]
    ) -> Dict[str, List[str]]:
        """Build directed graph of finding relationships."""
        graph: Dict[str, List[str]] = {f.id: [] for f in findings}
        
        for i, finding1 in enumerate(findings):
            for finding2 in findings[i+1:]:
                # Check if these finding types can form a chain
                if finding1.finding_type in self.ATTACK_RELATIONSHIPS:
                    if finding2.finding_type in self.ATTACK_RELATIONSHIPS[finding1.finding_type]:
                        graph[finding1.id].append(finding2.id)
                
                # Reverse direction
                if finding2.finding_type in self.ATTACK_RELATIONSHIPS:
                    if finding1.finding_type in self.ATTACK_RELATIONSHIPS[finding2.finding_type]:
                        graph[finding2.id].append(finding1.id)
        
        return graph
    
    def _detect_attack_patterns(self, findings: List[Finding]) -> List[AttackChain]:
        """Detect known attack chain patterns."""
        chains = []
        finding_map = {f.id: f for f in findings}
        
        for pattern in self.ATTACK_PATTERNS:
            # Find findings matching this pattern
            matches = self._find_pattern_matches(findings, pattern['pattern'])
            
            for match in matches:
                chain_findings = [finding_map[fid] for fid in match]
                
                self.chain_counter += 1
                chain = AttackChain(
                    id=f"chain_{self.chain_counter}",
                    name=pattern['name'],
                    findings=chain_findings,
                    steps=self._generate_steps(chain_findings, pattern['name']),
                    impact=pattern['impact'],
                    severity=self._calculate_chain_severity(chain_findings),
                    confidence=0.85,  # Known patterns have high confidence
                    business_impact=pattern['business_impact'],
                    technical_impact=pattern['technical_impact'],
                    exploitation_complexity=self._assess_complexity(chain_findings),
                    prerequisites=self._identify_prerequisites(chain_findings),
                    mitigations=self._suggest_mitigations(chain_findings)
                )
                chains.append(chain)
        
        return chains
    
    def _find_pattern_matches(
        self,
        findings: List[Finding],
        pattern: List[FindingType]
    ) -> List[List[str]]:
        """Find all matches of a finding type pattern."""
        matches = []
        
        if len(pattern) == 2:
            # Two-step pattern
            type1, type2 = pattern
            findings_type1 = [f for f in findings if f.finding_type == type1]
            findings_type2 = [f for f in findings if f.finding_type == type2]
            
            for f1 in findings_type1:
                for f2 in findings_type2:
                    # Check if they could be related (same domain, overlapping functionality)
                    if self._are_findings_related(f1, f2):
                        matches.append([f1.id, f2.id])
        
        return matches
    
    def _find_custom_chains(
        self,
        findings: List[Finding],
        relationships: Dict[str, List[str]]
    ) -> List[AttackChain]:
        """Find custom multi-step attack chains using graph traversal."""
        chains = []
        finding_map = {f.id: f for f in findings}
        visited_chains = set()
        
        # Find chains of length 3+
        for start_id in relationships:
            paths = self._find_paths(start_id, relationships, max_depth=4)
            
            for path in paths:
                if len(path) >= 3:  # Only interested in 3+ step chains
                    path_key = tuple(sorted(path))
                    if path_key in visited_chains:
                        continue
                    visited_chains.add(path_key)
                    
                    chain_findings = [finding_map[fid] for fid in path]
                    
                    self.chain_counter += 1
                    chain = AttackChain(
                        id=f"chain_{self.chain_counter}",
                        name=f"Multi-Step Attack Chain ({len(path)} steps)",
                        findings=chain_findings,
                        steps=self._generate_steps(chain_findings),
                        impact=self._assess_impact(chain_findings),
                        severity=self._calculate_chain_severity(chain_findings),
                        confidence=0.6,  # Custom chains have lower confidence
                        business_impact=self._describe_business_impact(chain_findings),
                        technical_impact=self._describe_technical_impact(chain_findings),
                        exploitation_complexity=self._assess_complexity(chain_findings),
                        prerequisites=self._identify_prerequisites(chain_findings),
                        mitigations=self._suggest_mitigations(chain_findings)
                    )
                    chains.append(chain)
        
        return chains
    
    def _find_paths(
        self,
        start: str,
        graph: Dict[str, List[str]],
        max_depth: int,
        visited: Optional[Set[str]] = None
    ) -> List[List[str]]:
        """Find all paths from start node up to max_depth."""
        if visited is None:
            visited = set()
        
        if max_depth == 0:
            return [[start]]
        
        paths = [[start]]
        visited.add(start)
        
        for neighbor in graph.get(start, []):
            if neighbor not in visited:
                sub_paths = self._find_paths(neighbor, graph, max_depth - 1, visited.copy())
                for sub_path in sub_paths:
                    paths.append([start] + sub_path)
        
        return paths
    
    def _are_findings_related(self, f1: Finding, f2: Finding) -> bool:
        """Check if two findings are potentially related."""
        # Same domain/host
        from urllib.parse import urlparse
        domain1 = urlparse(f1.affected_url).netloc
        domain2 = urlparse(f2.affected_url).netloc
        
        return domain1 == domain2
    
    def _generate_steps(
        self,
        findings: List[Finding],
        chain_name: str = ""
    ) -> List[str]:
        """Generate step-by-step attack description."""
        steps = []
        for i, finding in enumerate(findings, 1):
            steps.append(f"Step {i}: {finding.title}")
        return steps
    
    def _calculate_chain_severity(self, findings: List[Finding]) -> str:
        """Calculate overall chain severity."""
        severity_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        max_severity = max(
            (severity_scores.get(f.severity, 0) for f in findings),
            default=0
        )
        
        # Chain is at least as severe as highest finding, possibly higher
        for severity, score in severity_scores.items():
            if score == max_severity:
                # Upgrade severity if multiple findings
                if len(findings) >= 3 and max_severity < 4:
                    for sev, sc in severity_scores.items():
                        if sc == max_severity + 1:
                            return sev
                return severity
        
        return 'low'
    
    def _assess_impact(self, findings: List[Finding]) -> ImpactLevel:
        """Assess business impact of chain."""
        # Check finding types
        types = {f.finding_type for f in findings}
        
        if FindingType.AUTH_BYPASS in types or FindingType.INJECTION in types:
            return ImpactLevel.CRITICAL
        
        if FindingType.ACCESS_CONTROL in types:
            return ImpactLevel.HIGH
        
        if len(findings) >= 3:
            return ImpactLevel.HIGH
        
        return ImpactLevel.MEDIUM
    
    def _describe_business_impact(self, findings: List[Finding]) -> str:
        """Describe business impact of chain."""
        types = {f.finding_type for f in findings}
        
        if FindingType.AUTH_BYPASS in types:
            return "Unauthorized access to user accounts and sensitive data"
        if FindingType.INJECTION in types:
            return "Data breach, data manipulation, or system compromise"
        if FindingType.ACCESS_CONTROL in types:
            return "Unauthorized actions or privilege escalation"
        
        return "Security compromise through multi-step attack"
    
    def _describe_technical_impact(self, findings: List[Finding]) -> str:
        """Describe technical impact of chain."""
        return f"Chained exploitation of {len(findings)} vulnerabilities"
    
    def _assess_complexity(self, findings: List[Finding]) -> str:
        """Assess exploitation complexity."""
        if len(findings) >= 4:
            return 'high'
        if len(findings) == 3:
            return 'medium'
        return 'low'
    
    def _identify_prerequisites(self, findings: List[Finding]) -> List[str]:
        """Identify attack prerequisites."""
        prereqs = []
        
        types = {f.finding_type for f in findings}
        
        if FindingType.CSRF in types:
            prereqs.append("User must be authenticated")
            prereqs.append("Attacker must trick user into clicking link")
        
        if FindingType.XSS in types:
            prereqs.append("User must view malicious content")
        
        return prereqs
    
    def _suggest_mitigations(self, findings: List[Finding]) -> List[str]:
        """Suggest mitigations for chain."""
        mitigations = set()
        
        for finding in findings:
            if finding.finding_type == FindingType.INJECTION:
                mitigations.add("Input validation and parameterized queries")
            elif finding.finding_type == FindingType.XSS:
                mitigations.add("Output encoding and CSP headers")
            elif finding.finding_type == FindingType.CSRF:
                mitigations.add("CSRF tokens and SameSite cookies")
            elif finding.finding_type == FindingType.AUTH_BYPASS:
                mitigations.add("Strong authentication and session management")
        
        return list(mitigations)
    
    def _calculate_risk_score(self, result: CorrelationResult) -> float:
        """Calculate overall risk score (0-100)."""
        score = 0.0
        
        # Score from attack chains (weighted higher)
        for chain in result.attack_chains:
            severity_scores = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}
            score += severity_scores.get(chain.severity, 0) * chain.confidence
        
        # Score from standalone findings
        for finding in result.standalone_findings:
            severity_scores = {'critical': 15, 'high': 10, 'medium': 5, 'low': 2}
            score += severity_scores.get(finding.severity, 0)
        
        return min(100.0, score)
