"""
Reconnaissance API Routes

Endpoints for technology detection, version risk mapping, 
and scope verification.
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid
import httpx

from backend.services.tech_detector import TechDetector
from backend.services.version_risk import VersionRiskMapper
from backend.services.scope_validator import ScopeValidator
from backend.api.models.target import (
    Target,
    ScopeVerificationRequest,
    ScopeVerificationResponse,
    TargetListResponse
)


router = APIRouter(prefix="/recon", tags=["reconnaissance"])

# In-memory storage
recon_results: Dict[str, Dict[str, Any]] = {}
targets: Dict[str, Target] = {}


# Request/Response Models
class TechnologyDetectionRequest(BaseModel):
    """Request to detect technologies"""
    target_id: str
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    response_body: Optional[str] = None
    status_code: int = 200


class TechnologyDetectionResponse(BaseModel):
    """Technology detection response"""
    target_id: str
    url: str
    technologies: Dict[str, List[Dict[str, Any]]]
    raw_indicators: Dict[str, List[str]]
    timestamp: datetime


class VersionRiskRequest(BaseModel):
    """Request to map version risks"""
    technology: str
    version: str
    category: str


class VersionRisk(BaseModel):
    """Version risk information"""
    technology: str
    version: str
    risk_level: str
    known_cves: List[str]
    vulnerabilities: List[Dict[str, Any]]
    outdated: bool
    latest_version: Optional[str]
    recommendations: List[str]


class VersionRiskResponse(BaseModel):
    """Version risk mapping response"""
    risks: List[VersionRisk]
    overall_risk_level: str
    summary: str


class ReconResultsResponse(BaseModel):
    """Reconnaissance results for a target"""
    target_id: str
    technologies: Dict[str, List[Dict[str, Any]]]
    version_risks: List[VersionRisk]
    scope_verified: bool
    timestamp: datetime


# Routes
@router.post("/detect", response_model=TechnologyDetectionResponse, status_code=status.HTTP_200_OK)
async def detect_technologies(request: TechnologyDetectionRequest):
    """
    Run technology detection on a target.
    
    Analyzes HTTP headers, response body, and status codes to identify
    technologies, frameworks, and versions in use.
    """
    try:
        detector = TechDetector()
        
        # If headers and body are not provided, fetch the URL
        headers = request.headers
        body = request.response_body or ""
        
        if not headers or not body:
            try:
                async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
                    response = await client.get(request.url)
                    headers = dict(response.headers)
                    body = response.text
            except Exception as fetch_error:
                # If fetching fails, continue with empty headers/body
                pass
        
        # Run detection
        tech_stack = detector.detect(
            url=request.url,
            headers=headers,
            body=body
        )
        
        # Convert to dict format
        technologies = {
            "languages": [
                {
                    "name": tech.name,
                    "version": tech.version,
                    "confidence": tech.confidence,
                    "indicators": tech.indicators,
                    "category": tech.category
                }
                for tech in tech_stack.languages
            ],
            "frameworks": [
                {
                    "name": tech.name,
                    "version": tech.version,
                    "confidence": tech.confidence,
                    "indicators": tech.indicators,
                    "category": tech.category
                }
                for tech in tech_stack.frameworks
            ],
            "template_engines": [
                {
                    "name": tech.name,
                    "version": tech.version,
                    "confidence": tech.confidence,
                    "indicators": tech.indicators,
                    "category": tech.category
                }
                for tech in tech_stack.template_engines
            ],
            "web_servers": [
                {
                    "name": tech.name,
                    "version": tech.version,
                    "confidence": tech.confidence,
                    "indicators": tech.indicators,
                    "category": tech.category
                }
                for tech in tech_stack.web_servers
            ],
            "api_styles": [
                {
                    "name": tech.name,
                    "version": tech.version,
                    "confidence": tech.confidence,
                    "indicators": tech.indicators,
                    "category": tech.category
                }
                for tech in tech_stack.api_styles
            ]
        }
        
        # Store results
        if request.target_id not in recon_results:
            recon_results[request.target_id] = {}
        
        recon_results[request.target_id]["technologies"] = technologies
        recon_results[request.target_id]["raw_indicators"] = tech_stack.raw_indicators
        recon_results[request.target_id]["timestamp"] = datetime.now()
        
        return TechnologyDetectionResponse(
            target_id=request.target_id,
            url=request.url,
            technologies=technologies,
            raw_indicators=tech_stack.raw_indicators,
            timestamp=datetime.now()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Technology detection failed: {str(e)}"
        )


@router.get("/results/{target_id}", response_model=ReconResultsResponse, status_code=status.HTTP_200_OK)
async def get_recon_results(target_id: str):
    """
    Get reconnaissance results for a target.
    
    Returns all stored reconnaissance data including technologies,
    version risks, and scope verification status.
    """
    if target_id not in recon_results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No reconnaissance results found for target {target_id}"
        )
    
    results = recon_results[target_id]
    
    return ReconResultsResponse(
        target_id=target_id,
        technologies=results.get("technologies", {}),
        version_risks=results.get("version_risks", []),
        scope_verified=results.get("scope_verified", False),
        timestamp=results.get("timestamp", datetime.now())
    )


@router.post("/version-risk", response_model=VersionRiskResponse, status_code=status.HTTP_200_OK)
async def map_version_risks(request: VersionRiskRequest):
    """
    Map version risks for detected technologies.
    
    Analyzes technology versions against known vulnerability databases
    to identify security risks and outdated components.
    """
    try:
        mapper = VersionRiskMapper()
        
        # Assess risk for the technology version
        risk_assessment = mapper.assess_risk(
            technology=request.technology,
            version=request.version,
            category=request.category
        )
        
        # Create risk object
        version_risk = VersionRisk(
            technology=request.technology,
            version=request.version,
            risk_level=risk_assessment.get("risk_level", "unknown"),
            known_cves=risk_assessment.get("known_cves", []),
            vulnerabilities=risk_assessment.get("vulnerabilities", []),
            outdated=risk_assessment.get("outdated", False),
            latest_version=risk_assessment.get("latest_version"),
            recommendations=risk_assessment.get("recommendations", [])
        )
        
        # Determine overall risk
        overall_risk = risk_assessment.get("risk_level", "unknown")
        
        # Generate summary
        cve_count = len(risk_assessment.get("known_cves", []))
        vuln_count = len(risk_assessment.get("vulnerabilities", []))
        summary = f"{request.technology} {request.version}: {overall_risk.upper()} risk"
        if cve_count > 0:
            summary += f" ({cve_count} known CVEs, {vuln_count} vulnerabilities)"
        
        return VersionRiskResponse(
            risks=[version_risk],
            overall_risk_level=overall_risk,
            summary=summary
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Version risk mapping failed: {str(e)}"
        )


@router.post("/scope/verify", response_model=ScopeVerificationResponse, status_code=status.HTTP_200_OK)
async def verify_scope(request: ScopeVerificationRequest):
    """
    Verify if a target is in scope for testing.
    
    Validates URLs against scope rules to prevent out-of-scope testing.
    """
    try:
        validator = ScopeValidator()
        
        # Verify scope using is_in_scope method
        is_in_scope, message, warnings = validator.is_in_scope(request.url)
        
        # Get scope boundaries
        scope_boundaries = validator.get_scope_boundaries()
        
        return ScopeVerificationResponse(
            url=request.url,
            is_in_scope=is_in_scope,
            warnings=warnings,
            scope_boundaries=scope_boundaries,
            message=message
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scope verification failed: {str(e)}"
        )


@router.get("/scope/targets", response_model=TargetListResponse, status_code=status.HTTP_200_OK)
async def list_scoped_targets():
    """
    List all scoped targets.
    
    Returns all targets that have been verified and are in scope
    for security testing.
    """
    try:
        target_list = list(targets.values())
        
        # Return all targets
        return TargetListResponse(
            targets=target_list,
            total=len(target_list)
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list targets: {str(e)}"
        )
