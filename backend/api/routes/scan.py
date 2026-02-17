"""
Scan API Routes

Production-grade endpoints for orchestrating complete security scans.
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime

from backend.services.scan_engine import ScanEngine


router = APIRouter(prefix="/scan", tags=["scan"])

# Global scan engine instance
scan_engine = ScanEngine()


# Request/Response Models
class ScanRequest(BaseModel):
    """Request to start a new scan"""
    target_url: str
    endpoints: Optional[List[str]] = None
    parameters: Optional[List[str]] = None
    scan_options: Optional[Dict[str, Any]] = None


class ScanStartResponse(BaseModel):
    """Response for scan start"""
    scan_id: str
    message: str
    started_at: datetime


class ScanStatusResponse(BaseModel):
    """Response for scan status"""
    scan_id: str
    status: str
    current_phase: str
    progress: float
    phase_progress: Dict[str, float]
    logs: List[str]
    errors: List[str]


class ScanResultsResponse(BaseModel):
    """Response for scan results"""
    scan_id: str
    target: str
    tech_stack: Dict[str, Any]
    baseline_metrics: Dict[str, Any]
    misconfigurations: List[Dict[str, Any]]
    confirmed_vulnerabilities: List[Dict[str, Any]]
    suppressed_findings: List[Dict[str, Any]]
    attack_paths: List[Dict[str, Any]]
    overall_confidence: float
    status: str
    started_at: Optional[str]
    completed_at: Optional[str]


# Routes
@router.post("/start", response_model=ScanStartResponse, status_code=status.HTTP_201_CREATED)
async def start_scan(request: ScanRequest):
    """
    Start a new security scan.
    
    Initiates a complete 6-phase security assessment:
    1. Intelligence Gathering
    2. Baseline Profiling (15+ samples)
    3. Vulnerability Testing (multi-signal validation)
    4. Validation (reproducibility checks)
    5. Correlation (attack path analysis)
    6. Reporting
    
    All vulnerabilities are validated with:
    - Minimum 2 independent signals
    - 3x reproducibility requirement
    - Statistical anomaly detection
    - False positive suppression
    """
    try:
        # Prepare scan parameters
        params = {
            'endpoints': request.endpoints or [request.target_url],
            'parameters': request.parameters or [],
            'options': request.scan_options or {}
        }
        
        # Start scan
        scan_id = await scan_engine.start_scan(request.target_url, params)
        
        return ScanStartResponse(
            scan_id=scan_id,
            message="Scan started successfully",
            started_at=datetime.now()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start scan: {str(e)}"
        )


@router.get("/status/{scan_id}", response_model=ScanStatusResponse, status_code=status.HTTP_200_OK)
async def get_scan_status(scan_id: str):
    """
    Get real-time scan status.
    
    Returns:
    - Current execution phase
    - Progress percentage
    - Recent log entries
    - Any errors encountered
    """
    try:
        status_data = scan_engine.get_session_status(scan_id)
        
        if not status_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {scan_id} not found"
            )
        
        return ScanStatusResponse(
            scan_id=scan_id,
            status=status_data['status'],
            current_phase=status_data['current_phase'],
            progress=status_data['progress'],
            phase_progress=status_data['phase_progress'],
            logs=status_data['logs'],
            errors=status_data['errors']
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan status: {str(e)}"
        )


@router.get("/results/{scan_id}", response_model=ScanResultsResponse, status_code=status.HTTP_200_OK)
async def get_scan_results(scan_id: str):
    """
    Get complete scan results.
    
    Returns:
    - Detected technology stack
    - Statistical baseline metrics
    - Confirmed vulnerabilities (validated with multi-signal detection)
    - Suppressed findings (false positives)
    - Attack path correlations
    - Overall confidence score
    
    Only vulnerabilities meeting strict validation criteria are confirmed:
    - Reproducible 3+ times
    - At least 2 independent detection signals
    - Above statistical noise thresholds
    """
    try:
        results = scan_engine.get_session_results(scan_id)
        
        if not results:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {scan_id} not found"
            )
        
        return ScanResultsResponse(
            scan_id=scan_id,
            target=results['target'],
            tech_stack=results['tech_stack'],
            baseline_metrics=results['baseline_metrics'],
            misconfigurations=results['misconfigurations'],
            confirmed_vulnerabilities=results['confirmed_vulnerabilities'],
            suppressed_findings=results['suppressed_findings'],
            attack_paths=results['attack_paths'],
            overall_confidence=results['overall_confidence'],
            status=results['status'],
            started_at=results['started_at'],
            completed_at=results['completed_at']
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan results: {str(e)}"
        )


@router.get("/list", response_model=List[Dict[str, Any]], status_code=status.HTTP_200_OK)
async def list_scans():
    """
    List all scan sessions.
    
    Returns summary of all scans with their current status.
    """
    try:
        scans = []
        for scan_id, session in scan_engine.sessions.items():
            scans.append({
                'scan_id': scan_id,
                'target_url': session.target_url,
                'status': session.status.value,
                'current_phase': session.current_phase.value,
                'progress': session.progress,
                'started_at': session.started_at.isoformat(),
                'completed_at': session.completed_at.isoformat() if session.completed_at else None
            })
        
        return scans
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list scans: {str(e)}"
        )
