"""
Report API Routes

Endpoints for generating security reports, managing report lifecycle,
and calculating confidence scores.
"""
from fastapi import APIRouter, HTTPException, status, Query
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

from backend.services.report_generator import ReportGenerator
from backend.services.confidence_scorer import ConfidenceScorer
from backend.api.models.report import (
    Report,
    ReportRequest,
    ReportResponse,
    RetestRequest,
    RetestResponse,
    ReportFormat,
    ReportStatus
)
from backend.api.models.finding import Finding


router = APIRouter(prefix="/reports", tags=["reports"])

# In-memory storage
reports: Dict[str, Report] = {}
retest_results: Dict[str, List[Dict[str, Any]]] = {}


# Request/Response Models
class ReportListResponse(BaseModel):
    """Report list response"""
    reports: List[Report]
    total: int
    by_status: Dict[str, int] = Field(default_factory=dict)


class ConfidenceScoreRequest(BaseModel):
    """Request to calculate confidence score"""
    finding_id: str
    evidence_quality: Optional[str] = None  # high, medium, low
    reproduction_success_rate: Optional[float] = None  # 0.0 to 1.0
    false_positive_indicators: List[str] = Field(default_factory=list)


class ConfidenceScore(BaseModel):
    """Confidence score details"""
    finding_id: str
    overall_score: float  # 0.0 to 1.0
    confidence_level: str  # confirmed, high, medium, low, hypothesis
    factors: Dict[str, float]
    reasoning: List[str]
    recommendations: List[str]


class ConfidenceScoreResponse(BaseModel):
    """Confidence score response"""
    score: ConfidenceScore
    suggested_actions: List[str]
    timestamp: datetime


# Routes
@router.post("/generate", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_report(request: ReportRequest):
    """
    Generate a security report.
    
    Creates a comprehensive security report including findings,
    attack chains, statistics, and recommendations in the requested format.
    """
    try:
        generator = ReportGenerator()
        
        # Generate report
        report_data = await generator.generate(
            target_id=request.target_id,
            title=request.title,
            executive_summary=request.executive_summary,
            scope=request.scope,
            format=request.format.value,
            include_attack_chains=request.include_attack_chains
        )
        
        # Create report object
        report_id = str(uuid.uuid4())
        report = Report(
            id=report_id,
            title=request.title,
            target_id=request.target_id,
            target_url=report_data.get("target_url", ""),
            executive_summary=report_data.get("executive_summary", ""),
            scope=report_data.get("scope", ""),
            methodology=report_data.get("methodology", ""),
            findings=report_data.get("findings", []),
            attack_chains=report_data.get("attack_chains", []),
            total_findings=report_data.get("total_findings", 0),
            by_severity=report_data.get("by_severity", {}),
            by_type=report_data.get("by_type", {}),
            key_recommendations=report_data.get("key_recommendations", []),
            remediation_priority=report_data.get("remediation_priority", []),
            format=request.format,
            status=ReportStatus.DRAFT,
            version="1.0",
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        # Store report
        reports[report_id] = report
        
        # Generate download URL (mock)
        download_url = None
        if request.format != ReportFormat.JSON:
            download_url = f"/api/reports/{report_id}/download"
        
        return ReportResponse(
            report=report,
            download_url=download_url
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(e)}"
        )


@router.get("/", response_model=ReportListResponse, status_code=status.HTTP_200_OK)
async def list_reports(
    target_id: Optional[str] = Query(None, description="Filter by target ID"),
    status_filter: Optional[str] = Query(None, description="Filter by status", alias="status")
):
    """
    List all reports.
    
    Returns all generated reports with optional filtering by target
    and status, including statistics grouped by status.
    """
    try:
        # Start with all reports
        filtered_reports = list(reports.values())
        
        # Apply filters
        if target_id:
            filtered_reports = [r for r in filtered_reports if r.target_id == target_id]
        
        if status_filter:
            filtered_reports = [
                r for r in filtered_reports 
                if r.status.value == status_filter.lower()
            ]
        
        # Calculate statistics
        by_status = {}
        for report in filtered_reports:
            status_val = report.status.value
            by_status[status_val] = by_status.get(status_val, 0) + 1
        
        return ReportListResponse(
            reports=filtered_reports,
            total=len(filtered_reports),
            by_status=by_status
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list reports: {str(e)}"
        )


@router.get("/{report_id}", response_model=Report, status_code=status.HTTP_200_OK)
async def get_report(report_id: str):
    """
    Get a specific report by ID.
    
    Returns the full report including all findings, attack chains,
    and metadata.
    """
    if report_id not in reports:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report {report_id} not found"
        )
    
    return reports[report_id]


@router.post("/retest", response_model=RetestResponse, status_code=status.HTTP_200_OK)
async def log_retest_result(request: RetestRequest):
    """
    Log a retest result for a finding.
    
    Records the outcome of retesting a previously reported vulnerability,
    tracking whether it was fixed, partially fixed, or not fixed.
    """
    try:
        # Validate report exists
        if request.report_id not in reports:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report {request.report_id} not found"
            )
        
        # Validate status
        valid_statuses = ["fixed", "not_fixed", "partially_fixed"]
        if request.status not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            )
        
        # Store retest result
        if request.report_id not in retest_results:
            retest_results[request.report_id] = []
        
        retest_entry = {
            "finding_id": request.finding_id,
            "status": request.status,
            "notes": request.notes,
            "evidence": request.evidence,
            "timestamp": datetime.now()
        }
        retest_results[request.report_id].append(retest_entry)
        
        # Update report
        report = reports[request.report_id]
        report.retest_date = datetime.now()
        report.retest_notes = request.notes
        
        # Update report status if all findings are fixed
        if request.status == "fixed":
            # Check if this was the last unfixed finding
            all_fixed = all(
                r["status"] == "fixed" 
                for r in retest_results.get(request.report_id, [])
            )
            if all_fixed:
                report.status = ReportStatus.CLOSED
        else:
            report.status = ReportStatus.RETEST
        
        report.updated_at = datetime.now()
        
        # Generate message
        message = f"Retest result logged: {request.finding_id} is {request.status}"
        
        return RetestResponse(
            report_id=request.report_id,
            finding_id=request.finding_id,
            status=request.status,
            message=message
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to log retest result: {str(e)}"
        )


@router.get("/confidence/{finding_id}", response_model=ConfidenceScoreResponse, status_code=status.HTTP_200_OK)
async def get_confidence_score(
    finding_id: str,
    evidence_quality: Optional[str] = Query(None, description="Evidence quality: high, medium, low"),
    reproduction_rate: Optional[float] = Query(None, ge=0.0, le=1.0, description="Reproduction success rate")
):
    """
    Get confidence score for a finding.
    
    Calculates and returns a detailed confidence score based on
    evidence quality, reproduction success, and other factors.
    """
    try:
        scorer = ConfidenceScorer()
        
        # Calculate confidence score
        score_data = await scorer.calculate_score(
            finding_id=finding_id,
            evidence_quality=evidence_quality,
            reproduction_success_rate=reproduction_rate
        )
        
        # Create confidence score object
        confidence = ConfidenceScore(
            finding_id=finding_id,
            overall_score=score_data.get("overall_score", 0.5),
            confidence_level=score_data.get("confidence_level", "medium"),
            factors=score_data.get("factors", {}),
            reasoning=score_data.get("reasoning", []),
            recommendations=score_data.get("recommendations", [])
        )
        
        # Get suggested actions
        suggested_actions = score_data.get("suggested_actions", [])
        
        return ConfidenceScoreResponse(
            score=confidence,
            suggested_actions=suggested_actions,
            timestamp=datetime.now()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to calculate confidence score: {str(e)}"
        )
