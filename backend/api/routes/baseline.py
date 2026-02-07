"""
Baseline API Routes

Endpoints for capturing behavioral baselines and analyzing
security headers.
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

from backend.services.baseline_engine import BaselineEngine
from backend.services.header_analyzer import HeaderAnalyzer
from backend.api.models.baseline import (
    Baseline,
    BaselineRequest,
    BaselineResponse,
    SecurityHeaders,
    BaselineMetrics
)


router = APIRouter(prefix="/baseline", tags=["baseline"])

# In-memory storage
baselines: Dict[str, Baseline] = {}


# Request/Response Models
class HeaderAnalysisRequest(BaseModel):
    """Request to analyze security headers"""
    url: str
    headers: Dict[str, str]
    cookies: List[Dict[str, Any]] = Field(default_factory=list)


class HeaderAnalysisResponse(BaseModel):
    """Security header analysis response"""
    url: str
    security_headers: SecurityHeaders
    security_score: float
    issues: List[str]
    recommendations: List[str]
    timestamp: datetime


# Routes
@router.post("/capture", response_model=BaselineResponse, status_code=status.HTTP_201_CREATED)
async def capture_baseline(request: BaselineRequest):
    """
    Capture behavioral baseline for a target.
    
    Performs multiple requests to establish normal behavior patterns
    including response times, content lengths, status codes, and headers.
    This baseline is used to detect anomalies during testing.
    """
    try:
        engine = BaselineEngine()
        
        # Capture baseline
        baseline_data = await engine.capture_baseline(
            url=request.url,
            sample_size=request.sample_size
        )
        
        # Create baseline metrics
        metrics = BaselineMetrics(
            avg_response_time=baseline_data.get("avg_response_time", 0.0),
            std_response_time=baseline_data.get("std_response_time", 0.0),
            avg_content_length=baseline_data.get("avg_content_length", 0),
            std_content_length=baseline_data.get("std_content_length", 0),
            status_code_distribution=baseline_data.get("status_code_distribution", {}),
            common_status_codes=baseline_data.get("common_status_codes", []),
            common_headers=baseline_data.get("common_headers", {}),
            security_headers=baseline_data.get("security_headers_data", {}),
            error_patterns=baseline_data.get("error_patterns", []),
            success_patterns=baseline_data.get("success_patterns", [])
        )
        
        # Create security headers analysis
        security_headers = SecurityHeaders(
            csp=baseline_data.get("csp"),
            csp_effective=baseline_data.get("csp_effective", False),
            csp_issues=baseline_data.get("csp_issues", []),
            hsts=baseline_data.get("hsts"),
            hsts_enabled=baseline_data.get("hsts_enabled", False),
            hsts_max_age=baseline_data.get("hsts_max_age"),
            x_frame_options=baseline_data.get("x_frame_options"),
            clickjacking_protection=baseline_data.get("clickjacking_protection", False),
            x_content_type_options=baseline_data.get("x_content_type_options"),
            mime_sniffing_protection=baseline_data.get("mime_sniffing_protection", False),
            cors_policy=baseline_data.get("cors_policy"),
            cors_issues=baseline_data.get("cors_issues", []),
            cookies=baseline_data.get("cookies", []),
            cookie_issues=baseline_data.get("cookie_issues", [])
        )
        
        # Create baseline object
        baseline_id = str(uuid.uuid4())
        baseline = Baseline(
            id=baseline_id,
            target_id=request.target_id,
            url=request.url,
            metrics=metrics,
            security_headers=security_headers,
            technologies=baseline_data.get("technologies", []),
            sample_size=request.sample_size,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        # Store baseline
        baselines[request.target_id] = baseline
        
        # Generate insights and risk hypotheses
        insights = engine.generate_insights(baseline_data)
        risk_hypotheses = engine.generate_risk_hypotheses(baseline_data)
        
        return BaselineResponse(
            baseline=baseline,
            insights=insights,
            risk_hypotheses=risk_hypotheses
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Baseline capture failed: {str(e)}"
        )


@router.get("/{target_id}", response_model=Baseline, status_code=status.HTTP_200_OK)
async def get_baseline(target_id: str):
    """
    Get baseline data for a target.
    
    Returns the stored behavioral baseline including metrics,
    security headers, and detected technologies.
    """
    if target_id not in baselines:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No baseline found for target {target_id}"
        )
    
    return baselines[target_id]


@router.post("/analyze-headers", response_model=HeaderAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_headers(request: HeaderAnalysisRequest):
    """
    Analyze security headers for a target.
    
    Evaluates security-related HTTP headers and cookies to identify
    missing protections, misconfigurations, and security risks.
    """
    try:
        analyzer = HeaderAnalyzer()
        
        # Analyze headers
        analysis = analyzer.analyze(
            headers=request.headers,
            cookies=request.cookies
        )
        
        # Create security headers object
        security_headers = SecurityHeaders(
            csp=analysis.get("csp", {}).get("value"),
            csp_effective=analysis.get("csp", {}).get("effective", False),
            csp_issues=analysis.get("csp", {}).get("issues", []),
            hsts=analysis.get("hsts", {}).get("value"),
            hsts_enabled=analysis.get("hsts", {}).get("enabled", False),
            hsts_max_age=analysis.get("hsts", {}).get("max_age"),
            x_frame_options=analysis.get("x_frame_options", {}).get("value"),
            clickjacking_protection=analysis.get("x_frame_options", {}).get("protection", False),
            x_content_type_options=analysis.get("x_content_type_options", {}).get("value"),
            mime_sniffing_protection=analysis.get("x_content_type_options", {}).get("protection", False),
            cors_policy=analysis.get("cors", {}).get("policy"),
            cors_issues=analysis.get("cors", {}).get("issues", []),
            cookies=request.cookies,
            cookie_issues=analysis.get("cookie_issues", [])
        )
        
        # Calculate security score (0-100)
        security_score = analyzer.calculate_security_score(analysis)
        
        # Get issues and recommendations
        issues = analysis.get("issues", [])
        recommendations = analysis.get("recommendations", [])
        
        return HeaderAnalysisResponse(
            url=request.url,
            security_headers=security_headers,
            security_score=security_score,
            issues=issues,
            recommendations=recommendations,
            timestamp=datetime.now()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Header analysis failed: {str(e)}"
        )
