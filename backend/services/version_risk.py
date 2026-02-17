"""
Version Risk Mapping Service

Maps detected technology versions to known risk hypotheses and areas of focus.
Does NOT provide exploits - only suggests investigation areas based on version.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime, date, timezone
from enum import Enum


class RiskLevel(Enum):
    """Risk level classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RiskHypothesis:
    """Represents a risk hypothesis for a technology version."""
    
    technology: str
    version: str
    risk_level: RiskLevel
    title: str
    description: str
    focus_areas: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    eol_date: Optional[date] = None
    is_eol: bool = False


@dataclass
class VersionRiskProfile:
    """Complete risk profile for a technology version."""
    
    technology: str
    version: str
    hypotheses: List[RiskHypothesis] = field(default_factory=list)
    overall_risk: RiskLevel = RiskLevel.INFO
    is_outdated: bool = False
    latest_version: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)


class VersionRiskMapper:
    """
    Maps technology versions to known risk hypotheses.
    
    Identifies EOL versions, known vulnerability patterns, and suggests
    areas for security testing based on version-specific issues.
    """
    
    # End-of-Life dates for major versions
    EOL_DATES = {
        'PHP': {
            '5.6': date(2018, 12, 31),
            '7.0': date(2019, 1, 10),
            '7.1': date(2019, 12, 1),
            '7.2': date(2020, 11, 30),
            '7.3': date(2021, 12, 6),
            '7.4': date(2022, 11, 28),
            '8.0': date(2023, 11, 26),
        },
        'Django': {
            '1.11': date(2020, 4, 1),
            '2.2': date(2022, 4, 1),
            '3.2': date(2024, 4, 1),
        },
        'Rails': {
            '5.0': date(2018, 5, 1),
            '5.1': date(2018, 8, 1),
            '5.2': date(2022, 6, 1),
            '6.0': date(2023, 6, 1),
        },
        'Node.js': {
            '10': date(2021, 4, 30),
            '12': date(2022, 4, 30),
            '14': date(2023, 4, 30),
            '16': date(2023, 9, 11),
        },
    }
    
    # Version-specific risk hypotheses
    VERSION_RISKS = {
        'PHP': {
            '5.x': [
                RiskHypothesis(
                    technology='PHP',
                    version='5.x',
                    risk_level=RiskLevel.HIGH,
                    title='Type Juggling Vulnerabilities',
                    description='PHP 5.x has weak type comparison that may allow authentication bypasses and logic flaws.',
                    focus_areas=[
                        'Test == vs === comparisons in authentication',
                        'Check JSON parameter type handling',
                        'Test numeric string comparisons',
                        'Review password reset token validation'
                    ],
                    references=['https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf']
                ),
                RiskHypothesis(
                    technology='PHP',
                    version='5.x',
                    risk_level=RiskLevel.CRITICAL,
                    title='End of Life - No Security Updates',
                    description='PHP 5.x reached end of life and no longer receives security updates.',
                    focus_areas=['All common PHP vulnerabilities', 'Unpatched CVEs'],
                    is_eol=True
                ),
            ],
            '7.0': [
                RiskHypothesis(
                    technology='PHP',
                    version='7.0',
                    risk_level=RiskLevel.HIGH,
                    title='Unserialize Vulnerabilities',
                    description='PHP 7.0 has known object injection risks with unserialize().',
                    focus_areas=[
                        'Look for unserialize() usage',
                        'Test cookie deserialization',
                        'Check session handlers',
                        'Review API input processing'
                    ]
                ),
            ],
        },
        'Django': {
            '1.x': [
                RiskHypothesis(
                    technology='Django',
                    version='1.x',
                    risk_level=RiskLevel.MEDIUM,
                    title='SQL Injection in raw() and extra()',
                    description='Older Django versions have less safe raw SQL methods.',
                    focus_areas=[
                        'Test raw SQL queries with user input',
                        'Check .extra() query usage',
                        'Review custom query construction'
                    ]
                ),
            ],
            '2.x': [
                RiskHypothesis(
                    technology='Django',
                    version='2.x',
                    risk_level=RiskLevel.MEDIUM,
                    title='CSRF Token Bypass Potential',
                    description='Test CSRF protection implementation and edge cases.',
                    focus_areas=[
                        'Test CSRF token validation',
                        'Check AJAX request handling',
                        'Review @csrf_exempt usage'
                    ]
                ),
            ],
        },
        'Laravel': {
            '5.x': [
                RiskHypothesis(
                    technology='Laravel',
                    version='5.x',
                    risk_level=RiskLevel.MEDIUM,
                    title='Mass Assignment Vulnerabilities',
                    description='Improper fillable/guarded configuration may allow privilege escalation.',
                    focus_areas=[
                        'Test mass assignment on user models',
                        'Check role/permission field protection',
                        'Review API parameter binding'
                    ]
                ),
            ],
        },
        'Express': {
            '3.x': [
                RiskHypothesis(
                    technology='Express',
                    version='3.x',
                    risk_level=RiskLevel.MEDIUM,
                    title='Middleware Security Issues',
                    description='Older Express versions have middleware ordering and security issues.',
                    focus_areas=[
                        'Check body parser limits',
                        'Test parameter pollution',
                        'Review middleware chain'
                    ]
                ),
            ],
        },
        'Spring': {
            '4.x': [
                RiskHypothesis(
                    technology='Spring',
                    version='4.x',
                    risk_level=RiskLevel.HIGH,
                    title='Spring4Shell Vulnerability Class',
                    description='Spring 4.x may be vulnerable to class manipulation attacks.',
                    focus_areas=[
                        'Test parameter binding with class fields',
                        'Check ClassLoader manipulation',
                        'Review data binding security'
                    ]
                ),
            ],
        },
    }
    
    # Latest known stable versions (as of knowledge cutoff)
    LATEST_VERSIONS = {
        'PHP': '8.3',
        'Django': '5.0',
        'Laravel': '10.x',
        'Express': '4.x',
        'Rails': '7.x',
        'Spring': '6.x',
        'Node.js': '20.x',
    }
    
    def __init__(self):
        """Initialize version risk mapper."""
        pass
    
    def analyze_version(
        self,
        technology: str,
        version: Optional[str]
    ) -> VersionRiskProfile:
        """
        Analyze version for known risks and hypotheses.
        
        Args:
            technology: Technology name (e.g., 'PHP', 'Django')
            version: Version string (e.g., '7.4.3', '3.2')
            
        Returns:
            VersionRiskProfile with hypotheses and recommendations
        """
        profile = VersionRiskProfile(
            technology=technology,
            version=version or 'unknown'
        )
        
        if not version:
            profile.recommendations.append(
                "Unable to determine version - consider testing for multiple version-specific issues"
            )
            return profile
        
        # Check if version is EOL
        self._check_eol_status(technology, version, profile)
        
        # Get version-specific risk hypotheses
        self._add_risk_hypotheses(technology, version, profile)
        
        # Check if outdated
        self._check_if_outdated(technology, version, profile)
        
        # Determine overall risk level
        self._calculate_overall_risk(profile)
        
        # Generate recommendations
        self._generate_recommendations(profile)
        
        return profile
    
    def _check_eol_status(
        self,
        technology: str,
        version: str,
        profile: VersionRiskProfile
    ) -> None:
        """Check if version has reached end of life."""
        if technology not in self.EOL_DATES:
            return
        
        major_minor = self._extract_major_minor(version)
        eol_dates = self.EOL_DATES[technology]
        
        for eol_version, eol_date in eol_dates.items():
            if major_minor.startswith(eol_version) or major_minor == eol_version:
                if eol_date < datetime.now(timezone.utc).date():
                    hypothesis = RiskHypothesis(
                        technology=technology,
                        version=version,
                        risk_level=RiskLevel.CRITICAL,
                        title=f'{technology} {eol_version} End of Life',
                        description=f'This version reached end of life on {eol_date}. No security updates are available.',
                        focus_areas=[
                            'All known vulnerability classes for this version',
                            'Unpatched CVEs',
                            'Common framework-specific issues'
                        ],
                        eol_date=eol_date,
                        is_eol=True
                    )
                    profile.hypotheses.append(hypothesis)
                    break
    
    def _add_risk_hypotheses(
        self,
        technology: str,
        version: str,
        profile: VersionRiskProfile
    ) -> None:
        """Add version-specific risk hypotheses."""
        if technology not in self.VERSION_RISKS:
            return
        
        major_minor = self._extract_major_minor(version)
        major = major_minor.split('.')[0]
        
        # Check for exact matches and major version matches
        for risk_version, hypotheses in self.VERSION_RISKS[technology].items():
            if (major_minor.startswith(risk_version.rstrip('x.')) or
                major + '.x' == risk_version or
                major_minor == risk_version):
                profile.hypotheses.extend(hypotheses)
    
    def _check_if_outdated(
        self,
        technology: str,
        version: str,
        profile: VersionRiskProfile
    ) -> None:
        """Check if version is significantly outdated."""
        if technology not in self.LATEST_VERSIONS:
            return
        
        latest = self.LATEST_VERSIONS[technology]
        profile.latest_version = latest
        
        current_major = self._extract_major_minor(version).split('.')[0]
        latest_major = latest.rstrip('x.').split('.')[0]
        
        try:
            if int(current_major) < int(latest_major) - 1:
                profile.is_outdated = True
        except ValueError:
            pass
    
    def _calculate_overall_risk(self, profile: VersionRiskProfile) -> None:
        """Calculate overall risk level from hypotheses."""
        if not profile.hypotheses:
            profile.overall_risk = RiskLevel.INFO
            return
        
        risk_scores = {
            RiskLevel.CRITICAL: 4,
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 1,
            RiskLevel.INFO: 0
        }
        
        max_risk = max(
            (risk_scores[h.risk_level] for h in profile.hypotheses),
            default=0
        )
        
        for level, score in risk_scores.items():
            if score == max_risk:
                profile.overall_risk = level
                break
    
    def _generate_recommendations(self, profile: VersionRiskProfile) -> None:
        """Generate testing recommendations based on risk profile."""
        if profile.is_outdated:
            profile.recommendations.append(
                f"Version is outdated. Latest: {profile.latest_version}. "
                "Consider testing for known issues in this version range."
            )
        
        if profile.hypotheses:
            focus_areas = set()
            for hypothesis in profile.hypotheses:
                focus_areas.update(hypothesis.focus_areas)
            
            if focus_areas:
                profile.recommendations.append(
                    "Recommended testing focus areas based on version:"
                )
                profile.recommendations.extend([f"  - {area}" for area in sorted(focus_areas)])
    
    def _extract_major_minor(self, version: str) -> str:
        """Extract major.minor version from full version string."""
        parts = version.split('.')
        if len(parts) >= 2:
            return f"{parts[0]}.{parts[1]}"
        return parts[0] if parts else version
    
    def get_focus_areas(self, technology: str, version: Optional[str]) -> List[str]:
        """
        Get prioritized focus areas for testing.
        
        Args:
            technology: Technology name
            version: Version string
            
        Returns:
            List of testing focus areas
        """
        profile = self.analyze_version(technology, version)
        focus_areas = []
        
        for hypothesis in sorted(
            profile.hypotheses,
            key=lambda h: (h.risk_level.value, h.title)
        ):
            focus_areas.extend(hypothesis.focus_areas)
        
        return focus_areas
