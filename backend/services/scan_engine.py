"""
Production-Grade Scanning Engine

Orchestrates the complete 6-phase security testing workflow:
1. Intelligence Gathering
2. Baseline Profiling  
3. Vulnerability Testing
4. Validation
5. Correlation
6. Reporting

Enforces multi-signal validation and reproducibility requirements.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum
import hashlib
import statistics
import asyncio
import httpx
import uuid


class ScanPhase(Enum):
    """Scan execution phases"""
    INTELLIGENCE = "intelligence"
    BASELINE = "baseline"
    TESTING = "testing"
    VALIDATION = "validation"
    CORRELATION = "correlation"
    REPORTING = "reporting"


class ScanStatus(Enum):
    """Scan status"""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Signal:
    """Detection signal for vulnerability validation"""
    signal_type: str  # length_delta, hash_delta, timing_anomaly, status_change
    value: Any
    threshold: float
    confidence: float


@dataclass
class BaselineData:
    """Statistical baseline data"""
    sample_count: int
    mean_response_time: float
    stddev_response_time: float
    mean_content_length: float
    stddev_content_length: float
    status_codes: Dict[int, int]
    response_hashes: List[str]
    response_times: List[float]
    content_lengths: List[int]


@dataclass
class VulnerabilityFinding:
    """Confirmed vulnerability finding"""
    id: str
    type: str
    severity: str
    confidence: float
    parameter: str
    endpoint: str
    signals: List[Signal]
    reproducibility_count: int
    poc: str
    evidence: List[str]
    suppressed: bool = False
    suppression_reason: str = ""


@dataclass
class ScanSession:
    """Complete scan session data"""
    id: str
    target_url: str
    status: ScanStatus
    current_phase: ScanPhase
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    # Phase data
    tech_stack: Dict[str, Any] = field(default_factory=dict)
    baseline_metrics: Optional[BaselineData] = None
    misconfigurations: List[Dict[str, Any]] = field(default_factory=list)
    confirmed_vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    suppressed_findings: List[VulnerabilityFinding] = field(default_factory=list)
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    overall_confidence: float = 0.0
    
    # Progress tracking
    progress: float = 0.0
    phase_progress: Dict[str, float] = field(default_factory=dict)
    logs: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class ScanEngine:
    """
    Production-grade scanning engine with multi-signal validation.
    """
    
    # Minimum baseline samples required
    MIN_BASELINE_SAMPLES = 15
    
    # Statistical thresholds
    TIMING_THRESHOLD_STDDEV = 2.5
    LENGTH_THRESHOLD_STDDEV = 2.0
    
    # Reproducibility requirements
    MIN_REPRODUCIBILITY = 3
    MIN_SIGNALS = 2
    
    def __init__(self):
        """Initialize scan engine"""
        self.sessions: Dict[str, ScanSession] = {}
        
    async def start_scan(self, target_url: str, params: Dict[str, Any]) -> str:
        """
        Start a new scan session.
        
        Args:
            target_url: Target URL to scan
            params: Scan parameters (endpoints, parameters to test, etc.)
            
        Returns:
            Scan session ID
        """
        session_id = str(uuid.uuid4())
        session = ScanSession(
            id=session_id,
            target_url=target_url,
            status=ScanStatus.QUEUED,
            current_phase=ScanPhase.INTELLIGENCE,
            started_at=datetime.now()
        )
        self.sessions[session_id] = session
        
        # Start scan in background
        asyncio.create_task(self._execute_scan(session_id, params))
        
        return session_id
    
    async def _execute_scan(self, session_id: str, params: Dict[str, Any]):
        """Execute complete scan workflow"""
        session = self.sessions[session_id]
        session.status = ScanStatus.RUNNING
        
        try:
            # Phase 1: Intelligence Gathering
            await self._phase_intelligence(session)
            
            # Phase 2: Baseline Profiling
            await self._phase_baseline(session)
            
            # Phase 3: Vulnerability Testing
            await self._phase_testing(session, params)
            
            # Phase 4: Validation
            await self._phase_validation(session)
            
            # Phase 5: Correlation
            await self._phase_correlation(session)
            
            # Phase 6: Reporting
            await self._phase_reporting(session)
            
            session.status = ScanStatus.COMPLETED
            session.completed_at = datetime.now()
            
        except Exception as e:
            session.status = ScanStatus.FAILED
            session.errors.append(f"Scan failed: {str(e)}")
            session.completed_at = datetime.now()
    
    async def _phase_intelligence(self, session: ScanSession):
        """Phase 1: Intelligence gathering"""
        session.current_phase = ScanPhase.INTELLIGENCE
        session.logs.append("[Phase 1] Starting intelligence gathering...")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(session.target_url, timeout=10.0)
                
                # Extract server info
                session.tech_stack['server'] = response.headers.get('Server', 'Unknown')
                session.tech_stack['x_powered_by'] = response.headers.get('X-Powered-By', 'Unknown')
                
                # Store all headers
                session.tech_stack['headers'] = dict(response.headers)
                
                # Check security headers
                security_headers = {
                    'content_security_policy': 'Content-Security-Policy' in response.headers,
                    'x_frame_options': 'X-Frame-Options' in response.headers,
                    'strict_transport_security': 'Strict-Transport-Security' in response.headers,
                    'x_content_type_options': 'X-Content-Type-Options' in response.headers
                }
                session.tech_stack['security_headers'] = security_headers
                
                # Log missing security headers as misconfigurations
                for header, present in security_headers.items():
                    if not present:
                        session.misconfigurations.append({
                            'type': 'missing_security_header',
                            'header': header,
                            'severity': 'medium',
                            'requires_exploit_confirmation': True
                        })
                
                session.logs.append(f"[Phase 1] Detected server: {session.tech_stack['server']}")
                session.logs.append(f"[Phase 1] Security headers analyzed: {len(security_headers)} checked")
                
        except Exception as e:
            session.errors.append(f"Intelligence phase error: {str(e)}")
        
        session.phase_progress['intelligence'] = 1.0
        session.progress = 0.15
    
    async def _phase_baseline(self, session: ScanSession):
        """Phase 2: Baseline profiling with statistical analysis"""
        session.current_phase = ScanPhase.BASELINE
        session.logs.append(f"[Phase 2] Establishing baseline with {self.MIN_BASELINE_SAMPLES} samples...")
        
        response_times = []
        content_lengths = []
        status_codes = {}
        response_hashes = []
        
        try:
            async with httpx.AsyncClient() as client:
                for i in range(self.MIN_BASELINE_SAMPLES):
                    start_time = asyncio.get_event_loop().time()
                    response = await client.get(session.target_url, timeout=10.0)
                    end_time = asyncio.get_event_loop().time()
                    
                    response_time = end_time - start_time
                    content_length = len(response.content)
                    status_code = response.status_code
                    
                    # Calculate response hash
                    response_hash = hashlib.sha256(response.content).hexdigest()
                    
                    response_times.append(response_time)
                    content_lengths.append(content_length)
                    response_hashes.append(response_hash)
                    status_codes[status_code] = status_codes.get(status_code, 0) + 1
                    
                    if (i + 1) % 5 == 0:
                        session.logs.append(f"[Phase 2] Collected {i + 1}/{self.MIN_BASELINE_SAMPLES} baseline samples")
            
            # Calculate statistics
            mean_time = statistics.mean(response_times)
            stddev_time = statistics.stdev(response_times) if len(response_times) > 1 else 0.0
            mean_length = statistics.mean(content_lengths)
            stddev_length = statistics.stdev(content_lengths) if len(content_lengths) > 1 else 0.0
            
            session.baseline_metrics = BaselineData(
                sample_count=self.MIN_BASELINE_SAMPLES,
                mean_response_time=mean_time,
                stddev_response_time=stddev_time,
                mean_content_length=mean_length,
                stddev_content_length=stddev_length,
                status_codes=status_codes,
                response_hashes=response_hashes,
                response_times=response_times,
                content_lengths=content_lengths
            )
            
            session.logs.append(f"[Phase 2] Baseline established: mean_time={mean_time:.3f}s, stddev={stddev_time:.3f}s")
            session.logs.append(f"[Phase 2] Content length: mean={mean_length}, stddev={stddev_length:.1f}")
            
        except Exception as e:
            session.errors.append(f"Baseline phase error: {str(e)}")
            
        session.phase_progress['baseline'] = 1.0
        session.progress = 0.30
    
    async def _phase_testing(self, session: ScanSession, params: Dict[str, Any]):
        """Phase 3: Vulnerability testing with multi-signal detection"""
        session.current_phase = ScanPhase.TESTING
        session.logs.append("[Phase 3] Starting vulnerability testing...")
        
        if not session.baseline_metrics:
            session.errors.append("Baseline not established - cannot proceed with testing")
            return
        
        # Test parameters if provided
        test_params = params.get('parameters', [])
        endpoints = params.get('endpoints', [session.target_url])
        
        for endpoint in endpoints:
            for param_name in test_params:
                await self._test_parameter(session, endpoint, param_name)
        
        session.phase_progress['testing'] = 1.0
        session.progress = 0.60
    
    async def _test_parameter(self, session: ScanSession, endpoint: str, param_name: str):
        """Test individual parameter for vulnerabilities"""
        session.logs.append(f"[Phase 3] Testing parameter: {param_name}")
        
        # Test XSS
        await self._test_xss(session, endpoint, param_name)
        
        # Test SQLi  
        await self._test_sqli(session, endpoint, param_name)
    
    async def _test_xss(self, session: ScanSession, endpoint: str, param_name: str):
        """Test for XSS with multi-signal validation"""
        if not session.baseline_metrics:
            return
        
        # XSS payloads
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)"
        ]
        
        for payload in payloads:
            signals = []
            reproducible_count = 0
            evidence = []
            
            # Test reproducibility - must succeed 3 times
            for attempt in range(self.MIN_REPRODUCIBILITY):
                detected_signals = await self._test_payload(session, endpoint, param_name, payload)
                
                if len(detected_signals) >= self.MIN_SIGNALS:
                    reproducible_count += 1
                    if attempt == 0:
                        signals = detected_signals
                        evidence.append(f"Attempt {attempt + 1}: {len(detected_signals)} signals detected")
            
            # Confirm vulnerability if reproducible
            if reproducible_count >= self.MIN_REPRODUCIBILITY and len(signals) >= self.MIN_SIGNALS:
                finding = VulnerabilityFinding(
                    id=str(uuid.uuid4()),
                    type='xss',
                    severity='high',
                    confidence=min(1.0, reproducible_count / self.MIN_REPRODUCIBILITY),
                    parameter=param_name,
                    endpoint=endpoint,
                    signals=signals,
                    reproducibility_count=reproducible_count,
                    poc=f"GET {endpoint}?{param_name}={payload}",
                    evidence=evidence
                )
                session.confirmed_vulnerabilities.append(finding)
                session.logs.append(f"[Phase 3] ✓ XSS confirmed in {param_name}: {reproducible_count}x reproducible")
            elif len(signals) > 0:
                # Suppress as false positive
                finding = VulnerabilityFinding(
                    id=str(uuid.uuid4()),
                    type='xss',
                    severity='low',
                    confidence=0.0,
                    parameter=param_name,
                    endpoint=endpoint,
                    signals=signals,
                    reproducibility_count=reproducible_count,
                    poc="",
                    evidence=evidence,
                    suppressed=True,
                    suppression_reason=f"Not reproducible ({reproducible_count}/{self.MIN_REPRODUCIBILITY})"
                )
                session.suppressed_findings.append(finding)
    
    async def _test_sqli(self, session: ScanSession, endpoint: str, param_name: str):
        """Test for SQL injection with timing-based detection"""
        if not session.baseline_metrics:
            return
        
        # SQL timing payloads
        payloads = [
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "1' AND (SELECT SLEEP(5))--"
        ]
        
        for payload in payloads:
            signals = []
            reproducible_count = 0
            evidence = []
            
            # Test reproducibility
            for attempt in range(self.MIN_REPRODUCIBILITY):
                detected_signals = await self._test_payload(session, endpoint, param_name, payload)
                
                # Check for timing signal specifically
                timing_signals = [s for s in detected_signals if s.signal_type == 'timing_anomaly']
                
                if len(timing_signals) > 0:
                    reproducible_count += 1
                    if attempt == 0:
                        signals = detected_signals
                        evidence.append(f"Attempt {attempt + 1}: Timing anomaly detected")
            
            # Confirm if reproducible
            if reproducible_count >= self.MIN_REPRODUCIBILITY and len(signals) >= 1:
                finding = VulnerabilityFinding(
                    id=str(uuid.uuid4()),
                    type='sqli',
                    severity='critical',
                    confidence=min(1.0, reproducible_count / self.MIN_REPRODUCIBILITY),
                    parameter=param_name,
                    endpoint=endpoint,
                    signals=signals,
                    reproducibility_count=reproducible_count,
                    poc=f"GET {endpoint}?{param_name}={payload}",
                    evidence=evidence
                )
                session.confirmed_vulnerabilities.append(finding)
                session.logs.append(f"[Phase 3] ✓ SQLi confirmed in {param_name}: {reproducible_count}x reproducible")
            elif len(signals) > 0:
                # Suppress
                finding = VulnerabilityFinding(
                    id=str(uuid.uuid4()),
                    type='sqli',
                    severity='low',
                    confidence=0.0,
                    parameter=param_name,
                    endpoint=endpoint,
                    signals=signals,
                    reproducibility_count=reproducible_count,
                    poc="",
                    evidence=evidence,
                    suppressed=True,
                    suppression_reason=f"Not reproducible ({reproducible_count}/{self.MIN_REPRODUCIBILITY})"
                )
                session.suppressed_findings.append(finding)
    
    async def _test_payload(self, session: ScanSession, endpoint: str, param_name: str, payload: str) -> List[Signal]:
        """
        Test payload and detect signals.
        
        Returns list of detected signals.
        """
        if not session.baseline_metrics:
            return []
        
        baseline = session.baseline_metrics
        signals = []
        
        try:
            async with httpx.AsyncClient() as client:
                # Send request with payload
                params = {param_name: payload}
                start_time = asyncio.get_event_loop().time()
                response = await client.get(endpoint, params=params, timeout=15.0)
                end_time = asyncio.get_event_loop().time()
                
                response_time = end_time - start_time
                content_length = len(response.content)
                status_code = response.status_code
                response_hash = hashlib.sha256(response.content).hexdigest()
                
                # Signal 1: Timing anomaly
                if baseline.stddev_response_time > 0:
                    timing_deviation = (response_time - baseline.mean_response_time) / baseline.stddev_response_time
                    if abs(timing_deviation) > self.TIMING_THRESHOLD_STDDEV:
                        signals.append(Signal(
                            signal_type='timing_anomaly',
                            value=response_time,
                            threshold=self.TIMING_THRESHOLD_STDDEV,
                            confidence=min(1.0, abs(timing_deviation) / self.TIMING_THRESHOLD_STDDEV)
                        ))
                
                # Signal 2: Length delta
                if baseline.stddev_content_length > 0:
                    length_deviation = (content_length - baseline.mean_content_length) / baseline.stddev_content_length
                    if abs(length_deviation) > self.LENGTH_THRESHOLD_STDDEV:
                        signals.append(Signal(
                            signal_type='length_delta',
                            value=content_length,
                            threshold=self.LENGTH_THRESHOLD_STDDEV,
                            confidence=min(1.0, abs(length_deviation) / self.LENGTH_THRESHOLD_STDDEV)
                        ))
                
                # Signal 3: Hash delta (content changed)
                if response_hash not in baseline.response_hashes:
                    signals.append(Signal(
                        signal_type='hash_delta',
                        value=response_hash,
                        threshold=0.0,
                        confidence=0.8
                    ))
                
                # Signal 4: Status code change
                most_common_status = max(baseline.status_codes, key=baseline.status_codes.get)
                if status_code != most_common_status:
                    signals.append(Signal(
                        signal_type='status_change',
                        value=status_code,
                        threshold=0.0,
                        confidence=0.7
                    ))
                
        except Exception as e:
            session.errors.append(f"Payload test error: {str(e)}")
        
        return signals
    
    async def _phase_validation(self, session: ScanSession):
        """Phase 4: Validate findings"""
        session.current_phase = ScanPhase.VALIDATION
        session.logs.append(f"[Phase 4] Validating {len(session.confirmed_vulnerabilities)} findings...")
        
        # All findings already validated through reproducibility checks
        session.logs.append(f"[Phase 4] Confirmed: {len(session.confirmed_vulnerabilities)} vulnerabilities")
        session.logs.append(f"[Phase 4] Suppressed: {len(session.suppressed_findings)} false positives")
        
        session.phase_progress['validation'] = 1.0
        session.progress = 0.80
    
    async def _phase_correlation(self, session: ScanSession):
        """Phase 5: Correlate findings into attack paths"""
        session.current_phase = ScanPhase.CORRELATION
        session.logs.append("[Phase 5] Analyzing attack paths...")
        
        # Build attack paths from confirmed vulnerabilities
        for vuln in session.confirmed_vulnerabilities:
            session.attack_paths.append({
                'vulnerability_id': vuln.id,
                'type': vuln.type,
                'severity': vuln.severity,
                'endpoint': vuln.endpoint,
                'parameter': vuln.parameter
            })
        
        session.phase_progress['correlation'] = 1.0
        session.progress = 0.90
    
    async def _phase_reporting(self, session: ScanSession):
        """Phase 6: Generate final report"""
        session.current_phase = ScanPhase.REPORTING
        session.logs.append("[Phase 6] Generating report...")
        
        # Calculate overall confidence
        if session.confirmed_vulnerabilities:
            session.overall_confidence = sum(v.confidence for v in session.confirmed_vulnerabilities) / len(session.confirmed_vulnerabilities)
        else:
            session.overall_confidence = 0.0
        
        session.phase_progress['reporting'] = 1.0
        session.progress = 1.0
        session.logs.append("[Phase 6] Scan complete!")
    
    def get_session(self, session_id: str) -> Optional[ScanSession]:
        """Get scan session by ID"""
        return self.sessions.get(session_id)
    
    def get_session_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get scan session status"""
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        return {
            'id': session.id,
            'status': session.status.value,
            'current_phase': session.current_phase.value,
            'progress': session.progress,
            'phase_progress': session.phase_progress,
            'logs': session.logs[-10:],  # Last 10 logs
            'errors': session.errors
        }
    
    def get_session_results(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get complete scan results"""
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        return {
            'target': session.target_url,
            'tech_stack': session.tech_stack,
            'baseline_metrics': {
                'sample_count': session.baseline_metrics.sample_count if session.baseline_metrics else 0,
                'mean_response_time': session.baseline_metrics.mean_response_time if session.baseline_metrics else 0.0,
                'stddev_response_time': session.baseline_metrics.stddev_response_time if session.baseline_metrics else 0.0,
                'mean_content_length': session.baseline_metrics.mean_content_length if session.baseline_metrics else 0,
                'stddev_content_length': session.baseline_metrics.stddev_content_length if session.baseline_metrics else 0.0
            } if session.baseline_metrics else {},
            'misconfigurations': session.misconfigurations,
            'confirmed_vulnerabilities': [
                {
                    'id': v.id,
                    'type': v.type,
                    'severity': v.severity,
                    'confidence': v.confidence,
                    'parameter': v.parameter,
                    'endpoint': v.endpoint,
                    'reproducibility_count': v.reproducibility_count,
                    'signal_count': len(v.signals),
                    'poc': v.poc,
                    'evidence': v.evidence
                }
                for v in session.confirmed_vulnerabilities
            ],
            'suppressed_findings': [
                {
                    'id': v.id,
                    'type': v.type,
                    'parameter': v.parameter,
                    'suppression_reason': v.suppression_reason
                }
                for v in session.suppressed_findings
            ],
            'attack_paths': session.attack_paths,
            'overall_confidence': session.overall_confidence,
            'status': session.status.value,
            'started_at': session.started_at.isoformat(),
            'completed_at': session.completed_at.isoformat() if session.completed_at else None
        }
