"""
Confidence Scoring Engine

Scores security findings based on reproducibility, impact, evidence quality,
and exploitation complexity. Provides confidence levels and detailed breakdowns.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum


class ConfidenceLevel(Enum):
    """Confidence level classifications."""
    CONFIRMED = "confirmed"        # 90-100%
    HIGH = "high"                  # 75-89%
    MEDIUM = "medium"              # 50-74%
    LOW = "low"                    # 25-49%
    HYPOTHESIS = "hypothesis"      # 0-24%


@dataclass
class EvidenceQuality:
    """Quality assessment of evidence."""
    
    has_proof_of_concept: bool = False
    has_http_logs: bool = False
    has_screenshots: bool = False
    has_response_diff: bool = False
    reproducibility_steps: int = 0
    independently_verified: bool = False


@dataclass
class ConfidenceFactors:
    """Factors contributing to confidence score."""
    
    reproducibility_score: float = 0.0  # 0-30 points
    evidence_score: float = 0.0         # 0-25 points
    impact_score: float = 0.0           # 0-20 points
    fp_likelihood: float = 0.0          # 0-15 points (higher = less likely FP)
    exploit_difficulty: float = 0.0     # 0-10 points (higher = easier to exploit)
    
    def total_score(self) -> float:
        """Calculate total confidence score (0-100)."""
        return (
            self.reproducibility_score +
            self.evidence_score +
            self.impact_score +
            self.fp_likelihood +
            self.exploit_difficulty
        )


@dataclass
class ConfidenceScore:
    """Complete confidence scoring result."""
    
    level: ConfidenceLevel
    score: float  # 0-100
    factors: ConfidenceFactors
    reasoning: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class ConfidenceScorer:
    """
    Scores security finding confidence based on multiple factors.
    
    Evaluates reproducibility, evidence quality, impact, false positive
    likelihood, and exploitation difficulty to assign confidence levels.
    """
    
    # Severity to impact score mapping
    SEVERITY_IMPACT = {
        'critical': 20.0,
        'high': 15.0,
        'medium': 10.0,
        'low': 5.0,
        'info': 2.0,
    }
    
    # Finding type to false positive likelihood
    FP_LIKELIHOOD = {
        'injection': 0.85,      # SQL, Command injection - usually reliable
        'auth_bypass': 0.90,    # Auth issues - very reliable if verified
        'access_control': 0.80, # IDOR, privilege escalation
        'xss': 0.75,           # XSS can have context issues
        'csrf': 0.70,          # CSRF requires validation
        'info_disclosure': 0.60, # Often requires context
        'configuration': 0.85,   # Usually clear cut
        'crypto': 0.80,         # Crypto issues usually reliable
        'logic_flaw': 0.65,     # Context dependent
        'file_upload': 0.85,    # Usually clear
    }
    
    # Exploitation difficulty scoring
    EXPLOIT_DIFFICULTY = {
        'trivial': 10.0,      # Can be exploited with basic tools
        'low': 8.0,           # Requires some skill
        'medium': 5.0,        # Requires specialized knowledge
        'high': 3.0,          # Complex multi-step attack
        'very_high': 1.0,     # Theoretical or requires rare conditions
    }
    
    def __init__(self):
        """Initialize confidence scorer."""
        pass
    
    def score_finding(
        self,
        severity: str,
        finding_type: str,
        evidence: EvidenceQuality,
        attempts_to_reproduce: int = 1,
        successful_reproductions: int = 1,
        exploit_complexity: str = 'medium',
        requires_authentication: bool = False,
        requires_user_interaction: bool = False,
        custom_factors: Optional[Dict[str, float]] = None
    ) -> ConfidenceScore:
        """
        Score finding confidence.
        
        Args:
            severity: Finding severity ('critical', 'high', 'medium', 'low')
            finding_type: Type of finding (e.g., 'injection', 'xss')
            evidence: Evidence quality assessment
            attempts_to_reproduce: Number of reproduction attempts
            successful_reproductions: Number of successful reproductions
            exploit_complexity: Exploitation difficulty
            requires_authentication: Whether exploitation requires auth
            requires_user_interaction: Whether exploitation requires user action
            custom_factors: Optional custom scoring factors
            
        Returns:
            ConfidenceScore with level and breakdown
        """
        factors = ConfidenceFactors()
        reasoning = []
        warnings = []
        recommendations = []
        
        # Calculate reproducibility score (0-30)
        factors.reproducibility_score = self._score_reproducibility(
            attempts_to_reproduce,
            successful_reproductions,
            reasoning
        )
        
        # Calculate evidence quality score (0-25)
        factors.evidence_score = self._score_evidence(evidence, reasoning)
        
        # Calculate impact score (0-20)
        factors.impact_score = self._score_impact(severity, reasoning)
        
        # Calculate false positive likelihood (0-15)
        factors.fp_likelihood = self._score_fp_likelihood(
            finding_type,
            evidence,
            reasoning,
            warnings
        )
        
        # Calculate exploit difficulty (0-10)
        factors.exploit_difficulty = self._score_exploit_difficulty(
            exploit_complexity,
            requires_authentication,
            requires_user_interaction,
            reasoning
        )
        
        # Apply custom factors if provided
        if custom_factors:
            self._apply_custom_factors(factors, custom_factors, reasoning)
        
        # Calculate total score
        total_score = factors.total_score()
        
        # Determine confidence level
        level = self._determine_level(total_score)
        
        # Generate recommendations
        self._generate_recommendations(
            factors,
            evidence,
            level,
            recommendations
        )
        
        return ConfidenceScore(
            level=level,
            score=total_score,
            factors=factors,
            reasoning=reasoning,
            warnings=warnings,
            recommendations=recommendations
        )
    
    def _score_reproducibility(
        self,
        attempts: int,
        successful: int,
        reasoning: List[str]
    ) -> float:
        """Score reproducibility (0-30 points)."""
        if attempts == 0:
            reasoning.append("No reproduction attempts recorded (0 points)")
            return 0.0
        
        rate = successful / attempts
        
        if rate == 1.0 and successful >= 3:
            score = 30.0
            reasoning.append(f"100% reproducible across {successful} attempts (+30 points)")
        elif rate >= 0.8:
            score = 25.0
            reasoning.append(f"{rate:.0%} reproducibility rate (+25 points)")
        elif rate >= 0.5:
            score = 18.0
            reasoning.append(f"{rate:.0%} reproducibility rate (+18 points)")
        elif rate >= 0.3:
            score = 10.0
            reasoning.append(f"{rate:.0%} reproducibility rate (+10 points)")
        else:
            score = 5.0
            reasoning.append(f"Low reproducibility: {rate:.0%} (+5 points)")
        
        return score
    
    def _score_evidence(
        self,
        evidence: EvidenceQuality,
        reasoning: List[str]
    ) -> float:
        """Score evidence quality (0-25 points)."""
        score = 0.0
        
        if evidence.has_proof_of_concept:
            score += 8.0
            reasoning.append("Proof-of-concept provided (+8 points)")
        
        if evidence.has_http_logs:
            score += 6.0
            reasoning.append("HTTP request/response logs included (+6 points)")
        
        if evidence.has_screenshots:
            score += 4.0
            reasoning.append("Screenshots provided (+4 points)")
        
        if evidence.has_response_diff:
            score += 4.0
            reasoning.append("Response differences documented (+4 points)")
        
        if evidence.reproducibility_steps > 0:
            step_score = min(3.0, evidence.reproducibility_steps * 0.5)
            score += step_score
            reasoning.append(f"{evidence.reproducibility_steps} reproduction steps (+{step_score:.1f} points)")
        
        if evidence.independently_verified:
            score += 5.0
            reasoning.append("Independently verified (+5 points)")
        
        return min(25.0, score)
    
    def _score_impact(self, severity: str, reasoning: List[str]) -> float:
        """Score impact (0-20 points)."""
        score = self.SEVERITY_IMPACT.get(severity.lower(), 2.0)
        reasoning.append(f"Severity: {severity} (+{score:.1f} points)")
        return score
    
    def _score_fp_likelihood(
        self,
        finding_type: str,
        evidence: EvidenceQuality,
        reasoning: List[str],
        warnings: List[str]
    ) -> float:
        """Score false positive likelihood (0-15 points)."""
        base_reliability = self.FP_LIKELIHOOD.get(finding_type, 0.70)
        
        # Adjust based on evidence
        if evidence.independently_verified:
            base_reliability = min(0.98, base_reliability + 0.15)
        
        if evidence.has_proof_of_concept:
            base_reliability = min(0.98, base_reliability + 0.10)
        
        score = base_reliability * 15.0
        
        reasoning.append(
            f"False positive likelihood: {(1-base_reliability):.0%} "
            f"(+{score:.1f} points)"
        )
        
        if base_reliability < 0.70:
            warnings.append(
                "Higher than normal false positive risk - verify carefully"
            )
        
        return score
    
    def _score_exploit_difficulty(
        self,
        complexity: str,
        requires_auth: bool,
        requires_interaction: bool,
        reasoning: List[str]
    ) -> float:
        """Score exploitation difficulty (0-10 points)."""
        score = self.EXPLOIT_DIFFICULTY.get(complexity, 5.0)
        
        # Adjust for prerequisites
        if requires_auth:
            score *= 0.8
            reasoning.append("Requires authentication (-20%)")
        
        if requires_interaction:
            score *= 0.8
            reasoning.append("Requires user interaction (-20%)")
        
        reasoning.append(f"Exploit complexity: {complexity} (+{score:.1f} points)")
        
        return score
    
    def _apply_custom_factors(
        self,
        factors: ConfidenceFactors,
        custom: Dict[str, float],
        reasoning: List[str]
    ) -> None:
        """Apply custom scoring factors."""
        for factor_name, adjustment in custom.items():
            if factor_name == 'reproducibility':
                factors.reproducibility_score = min(30.0, factors.reproducibility_score + adjustment)
            elif factor_name == 'evidence':
                factors.evidence_score = min(25.0, factors.evidence_score + adjustment)
            elif factor_name == 'impact':
                factors.impact_score = min(20.0, factors.impact_score + adjustment)
            
            reasoning.append(f"Custom adjustment: {factor_name} ({adjustment:+.1f} points)")
    
    def _determine_level(self, score: float) -> ConfidenceLevel:
        """Determine confidence level from score."""
        if score >= 90:
            return ConfidenceLevel.CONFIRMED
        elif score >= 75:
            return ConfidenceLevel.HIGH
        elif score >= 50:
            return ConfidenceLevel.MEDIUM
        elif score >= 25:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.HYPOTHESIS
    
    def _generate_recommendations(
        self,
        factors: ConfidenceFactors,
        evidence: EvidenceQuality,
        level: ConfidenceLevel,
        recommendations: List[str]
    ) -> None:
        """Generate recommendations for improving confidence."""
        if factors.reproducibility_score < 20:
            recommendations.append(
                "Attempt to reproduce the finding multiple times to increase confidence"
            )
        
        if not evidence.has_proof_of_concept:
            recommendations.append(
                "Develop a proof-of-concept to demonstrate exploitability"
            )
        
        if not evidence.has_http_logs:
            recommendations.append(
                "Document complete HTTP request/response logs"
            )
        
        if not evidence.independently_verified and level in [ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW]:
            recommendations.append(
                "Consider independent verification by another tester"
            )
        
        if evidence.reproducibility_steps < 3:
            recommendations.append(
                "Document detailed step-by-step reproduction instructions"
            )
    
    def get_score_breakdown(self, score: ConfidenceScore) -> Dict[str, any]:
        """
        Get detailed score breakdown.
        
        Args:
            score: Confidence score to break down
            
        Returns:
            Dictionary with score breakdown
        """
        return {
            'level': score.level.value,
            'overall_score': f'{score.score:.1f}/100',
            'factors': {
                'reproducibility': f'{score.factors.reproducibility_score:.1f}/30',
                'evidence_quality': f'{score.factors.evidence_score:.1f}/25',
                'impact': f'{score.factors.impact_score:.1f}/20',
                'fp_reliability': f'{score.factors.fp_likelihood:.1f}/15',
                'exploit_ease': f'{score.factors.exploit_difficulty:.1f}/10',
            },
            'reasoning': score.reasoning,
            'warnings': score.warnings,
            'recommendations': score.recommendations,
        }
