"""
Behavioral Baseline Engine

Captures normal response characteristics and detects anomalies.
Uses statistical analysis to identify deviations from baseline behavior.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from datetime import datetime
import statistics
from enum import Enum


class AnomalyType(Enum):
    """Types of detected anomalies."""
    TIMING = "timing"
    SIZE = "size"
    STATUS_CODE = "status_code"
    HEADERS = "headers"
    CONTENT = "content"
    ERROR_PATTERN = "error_pattern"


@dataclass
class ResponseProfile:
    """Profile of a single HTTP response."""
    
    url: str
    method: str
    status_code: int
    response_time: float  # seconds
    content_length: int
    headers: Dict[str, str]
    timestamp: datetime = field(default_factory=lambda: datetime.now())
    content_sample: str = ""
    error_indicators: List[str] = field(default_factory=list)


@dataclass
class BaselineStats:
    """Statistical baseline for a response pattern."""
    
    sample_count: int = 0
    mean_response_time: float = 0.0
    stddev_response_time: float = 0.0
    mean_content_length: float = 0.0
    stddev_content_length: float = 0.0
    common_status_codes: Dict[int, int] = field(default_factory=dict)
    common_headers: Set[str] = field(default_factory=set)
    error_patterns: Dict[str, int] = field(default_factory=dict)
    response_times: List[float] = field(default_factory=list)
    content_lengths: List[int] = field(default_factory=list)


@dataclass
class Anomaly:
    """Detected anomaly from baseline."""
    
    anomaly_type: AnomalyType
    description: str
    severity: str  # 'high', 'medium', 'low'
    baseline_value: Any
    observed_value: Any
    deviation: float  # standard deviations from mean
    profile: ResponseProfile
    reasoning: str = ""


@dataclass
class BaselineAnalysis:
    """Complete baseline analysis result."""
    
    baseline: BaselineStats
    anomalies: List[Anomaly] = field(default_factory=list)
    is_established: bool = False
    confidence: float = 0.0


class BaselineEngine:
    """
    Behavioral baseline engine for detecting response anomalies.
    
    Builds statistical profiles of normal responses and identifies
    deviations that may indicate security issues or interesting behaviors.
    """
    
    # Minimum samples needed for reliable baseline
    MIN_SAMPLES = 5
    
    # Standard deviation multipliers for anomaly detection
    TIMING_THRESHOLD = 2.5  # 2.5 std devs
    SIZE_THRESHOLD = 2.0    # 2.0 std devs
    
    # Error pattern detection
    ERROR_PATTERNS = [
        (r'(?i)error', 'Generic error'),
        (r'(?i)exception', 'Exception thrown'),
        (r'(?i)stack trace', 'Stack trace'),
        (r'(?i)warning', 'Warning message'),
        (r'(?i)failed', 'Operation failed'),
        (r'(?i)denied', 'Access denied'),
        (r'(?i)forbidden', 'Forbidden access'),
        (r'(?i)unauthorized', 'Unauthorized'),
        (r'(?i)SQL syntax', 'SQL error'),
        (r'(?i)database', 'Database error'),
        (r'(?i)Fatal', 'Fatal error'),
    ]
    
    def __init__(self):
        """Initialize baseline engine."""
        self.baselines: Dict[str, BaselineStats] = {}
    
    def add_response(
        self,
        profile: ResponseProfile,
        baseline_key: Optional[str] = None
    ) -> None:
        """
        Add response to baseline.
        
        Args:
            profile: Response profile to add
            baseline_key: Key to group similar requests (defaults to URL path)
        """
        if baseline_key is None:
            baseline_key = self._generate_baseline_key(profile)
        
        if baseline_key not in self.baselines:
            self.baselines[baseline_key] = BaselineStats()
        
        baseline = self.baselines[baseline_key]
        
        # Update statistics
        baseline.sample_count += 1
        baseline.response_times.append(profile.response_time)
        baseline.content_lengths.append(profile.content_length)
        
        # Update status code distribution
        baseline.common_status_codes[profile.status_code] = \
            baseline.common_status_codes.get(profile.status_code, 0) + 1
        
        # Track common headers
        baseline.common_headers.update(profile.headers.keys())
        
        # Detect error patterns
        for indicator in profile.error_indicators:
            baseline.error_patterns[indicator] = \
                baseline.error_patterns.get(indicator, 0) + 1
        
        # Recalculate stats if we have enough samples
        if baseline.sample_count >= 2:
            baseline.mean_response_time = statistics.mean(baseline.response_times)
            baseline.mean_content_length = statistics.mean(baseline.content_lengths)
            
            if baseline.sample_count >= 3:
                baseline.stddev_response_time = statistics.stdev(baseline.response_times)
                baseline.stddev_content_length = statistics.stdev(baseline.content_lengths)
    
    def analyze_response(
        self,
        profile: ResponseProfile,
        baseline_key: Optional[str] = None
    ) -> BaselineAnalysis:
        """
        Analyze response against baseline to detect anomalies.
        
        Args:
            profile: Response profile to analyze
            baseline_key: Baseline key to compare against
            
        Returns:
            BaselineAnalysis with detected anomalies
        """
        if baseline_key is None:
            baseline_key = self._generate_baseline_key(profile)
        
        baseline = self.baselines.get(baseline_key)
        
        if not baseline:
            # No baseline yet - create one
            self.add_response(profile, baseline_key)
            return BaselineAnalysis(
                baseline=self.baselines[baseline_key],
                is_established=False,
                confidence=0.0
            )
        
        analysis = BaselineAnalysis(
            baseline=baseline,
            is_established=baseline.sample_count >= self.MIN_SAMPLES,
            confidence=min(1.0, baseline.sample_count / (self.MIN_SAMPLES * 2))
        )
        
        if not analysis.is_established:
            # Not enough samples yet
            self.add_response(profile, baseline_key)
            return analysis
        
        # Detect timing anomalies
        self._detect_timing_anomaly(profile, baseline, analysis)
        
        # Detect size anomalies
        self._detect_size_anomaly(profile, baseline, analysis)
        
        # Detect status code anomalies
        self._detect_status_anomaly(profile, baseline, analysis)
        
        # Detect header anomalies
        self._detect_header_anomaly(profile, baseline, analysis)
        
        # Detect error patterns
        self._detect_error_patterns(profile, baseline, analysis)
        
        # Add to baseline for continuous learning
        self.add_response(profile, baseline_key)
        
        return analysis
    
    def _detect_timing_anomaly(
        self,
        profile: ResponseProfile,
        baseline: BaselineStats,
        analysis: BaselineAnalysis
    ) -> None:
        """Detect response time anomalies."""
        if baseline.stddev_response_time == 0:
            return
        
        deviation = (profile.response_time - baseline.mean_response_time) / baseline.stddev_response_time
        
        if abs(deviation) > self.TIMING_THRESHOLD:
            severity = 'high' if abs(deviation) > 4 else 'medium'
            
            if deviation > 0:
                description = f'Response time significantly slower than baseline'
                reasoning = 'May indicate: rate limiting, backend delays, or different code path'
            else:
                description = f'Response time significantly faster than baseline'
                reasoning = 'May indicate: caching, early return, or error condition'
            
            analysis.anomalies.append(Anomaly(
                anomaly_type=AnomalyType.TIMING,
                description=description,
                severity=severity,
                baseline_value=f'{baseline.mean_response_time:.3f}s',
                observed_value=f'{profile.response_time:.3f}s',
                deviation=abs(deviation),
                profile=profile,
                reasoning=reasoning
            ))
    
    def _detect_size_anomaly(
        self,
        profile: ResponseProfile,
        baseline: BaselineStats,
        analysis: BaselineAnalysis
    ) -> None:
        """Detect content length anomalies."""
        if baseline.stddev_content_length == 0:
            return
        
        deviation = (profile.content_length - baseline.mean_content_length) / baseline.stddev_content_length
        
        if abs(deviation) > self.SIZE_THRESHOLD:
            severity = 'medium' if abs(deviation) > 3 else 'low'
            
            if deviation > 0:
                description = f'Response size significantly larger than baseline'
                reasoning = 'May indicate: data leakage, verbose errors, or different content'
            else:
                description = f'Response size significantly smaller than baseline'
                reasoning = 'May indicate: missing data, error response, or filtered output'
            
            analysis.anomalies.append(Anomaly(
                anomaly_type=AnomalyType.SIZE,
                description=description,
                severity=severity,
                baseline_value=f'{baseline.mean_content_length:.0f} bytes',
                observed_value=f'{profile.content_length} bytes',
                deviation=abs(deviation),
                profile=profile,
                reasoning=reasoning
            ))
    
    def _detect_status_anomaly(
        self,
        profile: ResponseProfile,
        baseline: BaselineStats,
        analysis: BaselineAnalysis
    ) -> None:
        """Detect unusual status codes."""
        if profile.status_code not in baseline.common_status_codes:
            severity = 'high' if profile.status_code >= 500 else 'medium'
            
            most_common = max(baseline.common_status_codes.items(), key=lambda x: x[1])[0]
            
            analysis.anomalies.append(Anomaly(
                anomaly_type=AnomalyType.STATUS_CODE,
                description=f'Unusual status code for this endpoint',
                severity=severity,
                baseline_value=f'Usually {most_common}',
                observed_value=str(profile.status_code),
                deviation=1.0,
                profile=profile,
                reasoning='Different status code may indicate error condition or access control'
            ))
    
    def _detect_header_anomaly(
        self,
        profile: ResponseProfile,
        baseline: BaselineStats,
        analysis: BaselineAnalysis
    ) -> None:
        """Detect unusual headers."""
        current_headers = set(profile.headers.keys())
        missing_headers = baseline.common_headers - current_headers
        new_headers = current_headers - baseline.common_headers
        
        if missing_headers:
            analysis.anomalies.append(Anomaly(
                anomaly_type=AnomalyType.HEADERS,
                description=f'Missing headers typically present',
                severity='low',
                baseline_value=', '.join(sorted(missing_headers)),
                observed_value='absent',
                deviation=1.0,
                profile=profile,
                reasoning='Missing headers may indicate different code path or error state'
            ))
        
        if new_headers:
            # Only flag if there are significant new headers
            debug_headers = [h for h in new_headers if 'debug' in h.lower() or 'error' in h.lower()]
            if debug_headers:
                analysis.anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.HEADERS,
                    description=f'Unexpected debug/error headers present',
                    severity='medium',
                    baseline_value='not present',
                    observed_value=', '.join(debug_headers),
                    deviation=1.0,
                    profile=profile,
                    reasoning='Debug headers may indicate error state or information disclosure'
                ))
    
    def _detect_error_patterns(
        self,
        profile: ResponseProfile,
        baseline: BaselineStats,
        analysis: BaselineAnalysis
    ) -> None:
        """Detect error patterns in response."""
        import re
        
        for pattern, description in self.ERROR_PATTERNS:
            if re.search(pattern, profile.content_sample):
                # Check if this is unusual for this endpoint
                if description not in baseline.error_patterns or \
                   baseline.error_patterns[description] < baseline.sample_count * 0.1:
                    
                    analysis.anomalies.append(Anomaly(
                        anomaly_type=AnomalyType.ERROR_PATTERN,
                        description=f'Error pattern detected: {description}',
                        severity='medium',
                        baseline_value='rarely seen',
                        observed_value='present in response',
                        deviation=1.0,
                        profile=profile,
                        reasoning='Error messages may reveal internal details or vulnerabilities'
                    ))
    
    def _generate_baseline_key(self, profile: ResponseProfile) -> str:
        """Generate baseline key from profile."""
        # Use method + URL path as key (ignoring query params)
        from urllib.parse import urlparse
        parsed = urlparse(profile.url)
        return f"{profile.method}:{parsed.path}"
    
    def get_baseline_summary(self, baseline_key: str) -> Optional[Dict[str, Any]]:
        """
        Get summary of baseline statistics.
        
        Args:
            baseline_key: Baseline key to summarize
            
        Returns:
            Summary dictionary or None if baseline doesn't exist
        """
        baseline = self.baselines.get(baseline_key)
        if not baseline:
            return None
        
        most_common_status = max(
            baseline.common_status_codes.items(),
            key=lambda x: x[1]
        )[0] if baseline.common_status_codes else None
        
        return {
            'sample_count': baseline.sample_count,
            'is_established': baseline.sample_count >= self.MIN_SAMPLES,
            'timing': {
                'mean': f'{baseline.mean_response_time:.3f}s',
                'stddev': f'{baseline.stddev_response_time:.3f}s',
            },
            'size': {
                'mean': f'{baseline.mean_content_length:.0f} bytes',
                'stddev': f'{baseline.stddev_content_length:.0f} bytes',
            },
            'most_common_status': most_common_status,
            'common_headers': sorted(baseline.common_headers),
            'error_patterns': baseline.error_patterns,
        }
