"""
Report Generation Engine

Generates professional security testing reports in multiple formats.
Follows hacker-style professional format with executive summaries,
detailed findings, attack chains, and remediation guidance.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from datetime import datetime
from enum import Enum
import json


class ReportFormat(Enum):
    """Supported report formats."""
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    PDF = "pdf"


@dataclass
class Finding:
    """Security finding for reporting."""
    
    id: str
    title: str
    severity: str
    confidence: str
    description: str
    affected_urls: List[str]
    reproduction_steps: List[str]
    evidence: List[str]
    impact: str
    remediation: str
    references: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None


@dataclass
class AttackChain:
    """Attack chain for reporting."""
    
    id: str
    name: str
    severity: str
    steps: List[str]
    findings: List[str]  # Finding IDs
    business_impact: str
    technical_impact: str
    exploitation_complexity: str
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class ReportMetadata:
    """Report metadata and scope."""
    
    target: str
    tester: str
    test_date: datetime
    report_date: datetime
    scope: List[str]
    out_of_scope: List[str] = field(default_factory=list)
    methodology: str = "Human-Reasoning Bug Hunting Framework"
    test_duration: Optional[str] = None


@dataclass
class ExecutiveSummary:
    """Executive summary data."""
    
    overview: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    key_findings: List[str]
    risk_rating: str
    recommendations: List[str]


class ReportGenerator:
    """
    Generates professional security testing reports.
    
    Creates structured reports with executive summaries, detailed findings,
    attack chains, and remediation guidance in multiple formats.
    """
    
    # Severity ordering and colors
    SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']
    SEVERITY_EMOJI = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🔵',
        'info': '⚪',
    }
    
    # CWE common categories
    CWE_CATEGORIES = {
        'injection': 'CWE-89: SQL Injection',
        'xss': 'CWE-79: Cross-site Scripting',
        'csrf': 'CWE-352: Cross-Site Request Forgery',
        'auth_bypass': 'CWE-287: Improper Authentication',
        'access_control': 'CWE-639: Insecure Direct Object Reference',
        'info_disclosure': 'CWE-200: Information Exposure',
    }
    
    def __init__(self):
        """Initialize report generator."""
        pass
    
    def generate_report(
        self,
        metadata: ReportMetadata,
        executive_summary: ExecutiveSummary,
        findings: List[Finding],
        attack_chains: Optional[List[AttackChain]] = None,
        format: ReportFormat = ReportFormat.MARKDOWN
    ) -> str:
        """
        Generate complete security report.
        
        Args:
            metadata: Report metadata and scope
            executive_summary: Executive summary data
            findings: List of security findings
            attack_chains: Optional attack chains
            format: Output format
            
        Returns:
            Report as string in requested format
        """
        if format == ReportFormat.MARKDOWN:
            return self._generate_markdown(
                metadata,
                executive_summary,
                findings,
                attack_chains or []
            )
        elif format == ReportFormat.JSON:
            return self._generate_json(
                metadata,
                executive_summary,
                findings,
                attack_chains or []
            )
        elif format == ReportFormat.HTML:
            return self._generate_html(
                metadata,
                executive_summary,
                findings,
                attack_chains or []
            )
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_markdown(
        self,
        metadata: ReportMetadata,
        summary: ExecutiveSummary,
        findings: List[Finding],
        chains: List[AttackChain]
    ) -> str:
        """Generate Markdown format report."""
        lines = []
        
        # Title and metadata
        lines.extend(self._md_header(metadata))
        lines.append("")
        
        # Table of contents
        lines.extend(self._md_toc(summary, findings, chains))
        lines.append("")
        
        # Executive summary
        lines.extend(self._md_executive_summary(summary))
        lines.append("")
        
        # Scope
        lines.extend(self._md_scope(metadata))
        lines.append("")
        
        # Attack chains (if any)
        if chains:
            lines.extend(self._md_attack_chains(chains, findings))
            lines.append("")
        
        # Findings by severity
        lines.extend(self._md_findings(findings))
        lines.append("")
        
        # Recommendations
        lines.extend(self._md_recommendations(summary))
        lines.append("")
        
        # Methodology
        lines.extend(self._md_methodology(metadata))
        
        return '\n'.join(lines)
    
    def _md_header(self, metadata: ReportMetadata) -> List[str]:
        """Generate Markdown header."""
        return [
            f"# Security Assessment Report",
            f"## {metadata.target}",
            "",
            f"**Tester:** {metadata.tester}  ",
            f"**Test Date:** {metadata.test_date.strftime('%Y-%m-%d')}  ",
            f"**Report Date:** {metadata.report_date.strftime('%Y-%m-%d')}  ",
            f"**Methodology:** {metadata.methodology}  ",
        ]
    
    def _md_toc(
        self,
        summary: ExecutiveSummary,
        findings: List[Finding],
        chains: List[AttackChain]
    ) -> List[str]:
        """Generate table of contents."""
        lines = [
            "## Table of Contents",
            "",
            "1. [Executive Summary](#executive-summary)",
            "2. [Scope](#scope)",
        ]
        
        section = 3
        if chains:
            lines.append(f"{section}. [Attack Chains](#attack-chains)")
            section += 1
        
        lines.append(f"{section}. [Findings](#findings)")
        
        for severity in self.SEVERITY_ORDER:
            count = self._count_by_severity(findings, severity)
            if count > 0:
                emoji = self.SEVERITY_EMOJI[severity]
                lines.append(f"   - [{emoji} {severity.title()} ({count})](#findings-{severity})")
        
        section += 1
        lines.append(f"{section}. [Recommendations](#recommendations)")
        lines.append(f"{section + 1}. [Methodology](#methodology)")
        
        return lines
    
    def _md_executive_summary(self, summary: ExecutiveSummary) -> List[str]:
        """Generate executive summary section."""
        lines = [
            "## Executive Summary",
            "",
            summary.overview,
            "",
            "### Findings Overview",
            "",
            f"**Total Findings:** {summary.total_findings}  ",
            f"**Overall Risk Rating:** {summary.risk_rating}  ",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {summary.critical_count} |",
            f"| 🟠 High | {summary.high_count} |",
            f"| 🟡 Medium | {summary.medium_count} |",
            f"| 🔵 Low | {summary.low_count} |",
            f"| ⚪ Info | {summary.info_count} |",
            "",
        ]
        
        if summary.key_findings:
            lines.append("### Key Findings")
            lines.append("")
            for finding in summary.key_findings:
                lines.append(f"- {finding}")
            lines.append("")
        
        return lines
    
    def _md_scope(self, metadata: ReportMetadata) -> List[str]:
        """Generate scope section."""
        lines = [
            "## Scope",
            "",
            "### In Scope",
            "",
        ]
        
        for item in metadata.scope:
            lines.append(f"- {item}")
        
        lines.append("")
        
        if metadata.out_of_scope:
            lines.append("### Out of Scope")
            lines.append("")
            for item in metadata.out_of_scope:
                lines.append(f"- {item}")
            lines.append("")
        
        return lines
    
    def _md_attack_chains(
        self,
        chains: List[AttackChain],
        findings: List[Finding]
    ) -> List[str]:
        """Generate attack chains section."""
        lines = [
            "## Attack Chains",
            "",
            "The following multi-step attack paths were identified by chaining individual vulnerabilities:",
            "",
        ]
        
        for i, chain in enumerate(chains, 1):
            emoji = self.SEVERITY_EMOJI.get(chain.severity, '⚪')
            lines.extend([
                f"### {i}. {emoji} {chain.name}",
                "",
                f"**Severity:** {chain.severity.title()}  ",
                f"**Complexity:** {chain.exploitation_complexity.title()}  ",
                "",
                "**Attack Steps:**",
                "",
            ])
            
            for step in chain.steps:
                lines.append(f"1. {step}")
            
            lines.append("")
            lines.append(f"**Business Impact:** {chain.business_impact}")
            lines.append("")
            lines.append(f"**Technical Impact:** {chain.technical_impact}")
            lines.append("")
            
            if chain.prerequisites:
                lines.append("**Prerequisites:**")
                lines.append("")
                for prereq in chain.prerequisites:
                    lines.append(f"- {prereq}")
                lines.append("")
        
        return lines
    
    def _md_findings(self, findings: List[Finding]) -> List[str]:
        """Generate findings section."""
        lines = [
            "## Findings",
            "",
        ]
        
        # Group by severity
        for severity in self.SEVERITY_ORDER:
            severity_findings = [f for f in findings if f.severity == severity]
            if not severity_findings:
                continue
            
            emoji = self.SEVERITY_EMOJI[severity]
            lines.extend([
                f"### {emoji} {severity.title()} Severity Findings {{#findings-{severity}}}",
                "",
            ])
            
            for i, finding in enumerate(severity_findings, 1):
                lines.extend(self._md_finding_detail(finding, i))
                lines.append("")
        
        return lines
    
    def _md_finding_detail(self, finding: Finding, index: int) -> List[str]:
        """Generate detailed finding entry."""
        lines = [
            f"#### {index}. {finding.title}",
            "",
            f"**Severity:** {finding.severity.title()}  ",
            f"**Confidence:** {finding.confidence.title()}  ",
        ]
        
        if finding.cvss_score:
            lines.append(f"**CVSS Score:** {finding.cvss_score}  ")
        
        if finding.cwe_id:
            lines.append(f"**CWE:** {finding.cwe_id}  ")
        
        lines.extend([
            "",
            "**Description:**",
            "",
            finding.description,
            "",
            "**Affected URLs:**",
            "",
        ])
        
        for url in finding.affected_urls:
            lines.append(f"- `{url}`")
        
        lines.extend([
            "",
            "**Impact:**",
            "",
            finding.impact,
            "",
            "**Reproduction Steps:**",
            "",
        ])
        
        for i, step in enumerate(finding.reproduction_steps, 1):
            lines.append(f"{i}. {step}")
        
        lines.append("")
        
        if finding.evidence:
            lines.extend([
                "**Evidence:**",
                "",
            ])
            for evidence in finding.evidence:
                lines.append(f"```")
                lines.append(evidence)
                lines.append(f"```")
                lines.append("")
        
        lines.extend([
            "**Remediation:**",
            "",
            finding.remediation,
            "",
        ])
        
        if finding.references:
            lines.extend([
                "**References:**",
                "",
            ])
            for ref in finding.references:
                lines.append(f"- {ref}")
            lines.append("")
        
        lines.append("---")
        
        return lines
    
    def _md_recommendations(self, summary: ExecutiveSummary) -> List[str]:
        """Generate recommendations section."""
        lines = [
            "## Recommendations",
            "",
            "Based on the identified vulnerabilities, the following remediation actions are recommended:",
            "",
        ]
        
        for i, rec in enumerate(summary.recommendations, 1):
            lines.append(f"{i}. {rec}")
        
        return lines
    
    def _md_methodology(self, metadata: ReportMetadata) -> List[str]:
        """Generate methodology section."""
        return [
            "## Methodology",
            "",
            f"This assessment was conducted using the **{metadata.methodology}**, which emphasizes:",
            "",
            "- **Human reasoning** over automated scanning",
            "- **Hypothesis-driven testing** based on observations",
            "- **Contextual analysis** of application behavior",
            "- **Minimal intrusion** and safe testing practices",
            "- **Evidence-based findings** with reproducible steps",
            "",
            "The testing approach focuses on understanding the application's logic, identifying attack surfaces, "
            "and systematically exploring potential security weaknesses through manual analysis and targeted testing.",
        ]
    
    def _generate_json(
        self,
        metadata: ReportMetadata,
        summary: ExecutiveSummary,
        findings: List[Finding],
        chains: List[AttackChain]
    ) -> str:
        """Generate JSON format report."""
        report = {
            'metadata': {
                'target': metadata.target,
                'tester': metadata.tester,
                'test_date': metadata.test_date.isoformat(),
                'report_date': metadata.report_date.isoformat(),
                'methodology': metadata.methodology,
                'scope': metadata.scope,
                'out_of_scope': metadata.out_of_scope,
            },
            'executive_summary': {
                'overview': summary.overview,
                'total_findings': summary.total_findings,
                'severity_breakdown': {
                    'critical': summary.critical_count,
                    'high': summary.high_count,
                    'medium': summary.medium_count,
                    'low': summary.low_count,
                    'info': summary.info_count,
                },
                'risk_rating': summary.risk_rating,
                'key_findings': summary.key_findings,
                'recommendations': summary.recommendations,
            },
            'attack_chains': [
                {
                    'id': chain.id,
                    'name': chain.name,
                    'severity': chain.severity,
                    'steps': chain.steps,
                    'findings': chain.findings,
                    'business_impact': chain.business_impact,
                    'technical_impact': chain.technical_impact,
                    'exploitation_complexity': chain.exploitation_complexity,
                    'prerequisites': chain.prerequisites,
                }
                for chain in chains
            ],
            'findings': [
                {
                    'id': f.id,
                    'title': f.title,
                    'severity': f.severity,
                    'confidence': f.confidence,
                    'description': f.description,
                    'affected_urls': f.affected_urls,
                    'reproduction_steps': f.reproduction_steps,
                    'evidence': f.evidence,
                    'impact': f.impact,
                    'remediation': f.remediation,
                    'references': f.references,
                    'cvss_score': f.cvss_score,
                    'cwe_id': f.cwe_id,
                }
                for f in findings
            ],
        }
        
        return json.dumps(report, indent=2)
    
    def _generate_html(
        self,
        metadata: ReportMetadata,
        summary: ExecutiveSummary,
        findings: List[Finding],
        chains: List[AttackChain]
    ) -> str:
        """Generate HTML format report."""
        # Generate markdown first, then wrap in HTML template
        md_content = self._generate_markdown(metadata, summary, findings, chains)
        
        # Simple HTML wrapper (in production, use proper markdown-to-HTML converter)
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {metadata.target}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
        }}
        h1, h2, h3, h4 {{ color: #2c3e50; }}
        h1 {{ border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ border-bottom: 2px solid #95a5a6; padding-bottom: 8px; margin-top: 40px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        code {{ background-color: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
        pre {{ background-color: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f39c12; font-weight: bold; }}
        .low {{ color: #3498db; font-weight: bold; }}
        .info {{ color: #95a5a6; }}
    </style>
</head>
<body>
    <pre>{md_content}</pre>
</body>
</html>"""
        
        return html
    
    def _count_by_severity(self, findings: List[Finding], severity: str) -> int:
        """Count findings by severity."""
        return len([f for f in findings if f.severity == severity])
    
    def create_executive_summary(
        self,
        findings: List[Finding],
        overview: str,
        risk_rating: str = "Medium",
        key_findings: Optional[List[str]] = None,
        recommendations: Optional[List[str]] = None
    ) -> ExecutiveSummary:
        """
        Create executive summary from findings.
        
        Args:
            findings: List of all findings
            overview: Summary overview text
            risk_rating: Overall risk rating
            key_findings: Optional list of key findings
            recommendations: Optional list of recommendations
            
        Returns:
            ExecutiveSummary object
        """
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }
        
        for finding in findings:
            severity = finding.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Auto-generate key findings if not provided
        if key_findings is None:
            key_findings = []
            # Take critical and high severity findings as key findings
            for f in findings:
                if f.severity in ['critical', 'high'] and len(key_findings) < 5:
                    key_findings.append(f"{f.title} ({f.severity})")
        
        # Auto-generate recommendations if not provided
        if recommendations is None:
            recommendations = [
                "Address all Critical and High severity findings immediately",
                "Implement security controls identified in remediation sections",
                "Conduct regular security assessments",
                "Establish secure development practices",
            ]
        
        return ExecutiveSummary(
            overview=overview,
            total_findings=len(findings),
            critical_count=severity_counts['critical'],
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
            info_count=severity_counts['info'],
            key_findings=key_findings,
            risk_rating=risk_rating,
            recommendations=recommendations
        )
