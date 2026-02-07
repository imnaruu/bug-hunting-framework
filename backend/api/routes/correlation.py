"""
Correlation API Routes

Endpoints for running correlation engine, identifying attack chains,
and translating business impact.
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

from backend.services.correlation_engine import CorrelationEngine
from backend.api.models.finding import Finding, Severity
from backend.api.models.report import AttackChain


router = APIRouter(prefix="/correlation", tags=["correlation"])

# In-memory storage
attack_chains: Dict[str, AttackChain] = {}
correlation_results: Dict[str, Dict[str, Any]] = {}


# Request/Response Models
class CorrelationRequest(BaseModel):
    """Request to run correlation engine"""
    target_id: str
    finding_ids: List[str]
    include_hypothetical: bool = False
    max_chain_length: int = 5


class CorrelatedFinding(BaseModel):
    """Correlated finding with relationship info"""
    finding_id: str
    relationship_type: str  # prerequisite, enabler, amplifier, parallel
    strength: float  # 0.0 to 1.0
    description: str


class CorrelationResult(BaseModel):
    """Correlation analysis result"""
    finding_id: str
    correlated_findings: List[CorrelatedFinding]
    attack_chains: List[str]  # Chain IDs
    correlation_score: float
    insights: List[str]


class CorrelationResponse(BaseModel):
    """Correlation engine response"""
    target_id: str
    results: List[CorrelationResult]
    total_correlations: int
    attack_chains_identified: int
    timestamp: datetime


class AttackChainListResponse(BaseModel):
    """Attack chain list response"""
    chains: List[AttackChain]
    total: int


class BusinessImpactRequest(BaseModel):
    """Request to translate business impact"""
    finding_ids: List[str]
    attack_chain_id: Optional[str] = None
    business_context: Optional[Dict[str, Any]] = None


class BusinessImpact(BaseModel):
    """Business impact analysis"""
    finding_id: Optional[str] = None
    attack_chain_id: Optional[str] = None
    business_impact: str
    financial_impact: Optional[str] = None
    reputational_impact: Optional[str] = None
    compliance_impact: Optional[str] = None
    operational_impact: Optional[str] = None
    attack_scenarios: List[str]
    affected_stakeholders: List[str]
    urgency: str  # critical, high, medium, low


class BusinessImpactResponse(BaseModel):
    """Business impact translation response"""
    impacts: List[BusinessImpact]
    overall_risk_level: str
    executive_summary: str
    key_recommendations: List[str]


# Routes
@router.post("/", response_model=CorrelationResponse, status_code=status.HTTP_200_OK)
async def run_correlation(request: CorrelationRequest):
    """
    Run correlation engine on findings.
    
    Analyzes relationships between findings to identify attack chains,
    compound vulnerabilities, and exploitation paths.
    """
    try:
        engine = CorrelationEngine()
        
        # Run correlation analysis
        correlation_data = await engine.correlate_findings(
            target_id=request.target_id,
            finding_ids=request.finding_ids,
            include_hypothetical=request.include_hypothetical,
            max_chain_length=request.max_chain_length
        )
        
        # Process results
        results = []
        total_correlations = 0
        chains_identified = 0
        
        for finding_id, data in correlation_data.items():
            # Create correlated findings
            correlated = []
            for corr in data.get("correlations", []):
                correlated.append(CorrelatedFinding(
                    finding_id=corr.get("finding_id"),
                    relationship_type=corr.get("relationship_type", "related"),
                    strength=corr.get("strength", 0.5),
                    description=corr.get("description", "")
                ))
            
            total_correlations += len(correlated)
            
            # Get attack chains
            chain_ids = data.get("attack_chains", [])
            
            # Create attack chain objects if not exist
            for chain_data in data.get("chain_details", []):
                chain_id = chain_data.get("id", str(uuid.uuid4()))
                if chain_id not in attack_chains:
                    attack_chain = AttackChain(
                        id=chain_id,
                        name=chain_data.get("name", "Unnamed Attack Chain"),
                        description=chain_data.get("description", ""),
                        findings=chain_data.get("findings", []),
                        steps=chain_data.get("steps", []),
                        business_impact=chain_data.get("business_impact", ""),
                        severity=Severity(chain_data.get("severity", "medium")),
                        exploitability=chain_data.get("exploitability", "medium")
                    )
                    attack_chains[chain_id] = attack_chain
                    chains_identified += 1
            
            # Create result
            result = CorrelationResult(
                finding_id=finding_id,
                correlated_findings=correlated,
                attack_chains=chain_ids,
                correlation_score=data.get("correlation_score", 0.0),
                insights=data.get("insights", [])
            )
            results.append(result)
        
        # Store correlation results
        correlation_id = str(uuid.uuid4())
        correlation_results[correlation_id] = {
            "target_id": request.target_id,
            "results": results,
            "timestamp": datetime.now()
        }
        
        return CorrelationResponse(
            target_id=request.target_id,
            results=results,
            total_correlations=total_correlations,
            attack_chains_identified=chains_identified,
            timestamp=datetime.now()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Correlation analysis failed: {str(e)}"
        )


@router.get("/chains", response_model=AttackChainListResponse, status_code=status.HTTP_200_OK)
async def get_attack_chains(
    target_id: Optional[str] = None,
    severity: Optional[str] = None
):
    """
    Get identified attack chains.
    
    Returns all discovered attack chains, optionally filtered
    by target and severity.
    """
    try:
        # Filter chains
        filtered_chains = list(attack_chains.values())
        
        # Note: We don't have target_id in AttackChain model, 
        # so we skip target_id filtering for now
        
        if severity:
            filtered_chains = [
                c for c in filtered_chains 
                if c.severity.value == severity.lower()
            ]
        
        return AttackChainListResponse(
            chains=filtered_chains,
            total=len(filtered_chains)
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get attack chains: {str(e)}"
        )


@router.post("/impact", response_model=BusinessImpactResponse, status_code=status.HTTP_200_OK)
async def translate_business_impact(request: BusinessImpactRequest):
    """
    Translate technical findings to business impact.
    
    Converts technical vulnerability details into business terms,
    quantifying financial, reputational, and operational risks.
    """
    try:
        engine = CorrelationEngine()
        
        # Analyze business impact
        impact_data = await engine.analyze_business_impact(
            finding_ids=request.finding_ids,
            attack_chain_id=request.attack_chain_id,
            business_context=request.business_context or {}
        )
        
        # Process impacts
        impacts = []
        for impact in impact_data.get("impacts", []):
            business_impact = BusinessImpact(
                finding_id=impact.get("finding_id"),
                attack_chain_id=impact.get("attack_chain_id"),
                business_impact=impact.get("business_impact", ""),
                financial_impact=impact.get("financial_impact"),
                reputational_impact=impact.get("reputational_impact"),
                compliance_impact=impact.get("compliance_impact"),
                operational_impact=impact.get("operational_impact"),
                attack_scenarios=impact.get("attack_scenarios", []),
                affected_stakeholders=impact.get("affected_stakeholders", []),
                urgency=impact.get("urgency", "medium")
            )
            impacts.append(business_impact)
        
        # Generate executive summary
        executive_summary = impact_data.get(
            "executive_summary",
            "Business impact analysis completed for identified vulnerabilities."
        )
        
        # Get overall risk level
        overall_risk = impact_data.get("overall_risk_level", "medium")
        
        # Get recommendations
        recommendations = impact_data.get("recommendations", [])
        
        return BusinessImpactResponse(
            impacts=impacts,
            overall_risk_level=overall_risk,
            executive_summary=executive_summary,
            key_recommendations=recommendations
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Business impact analysis failed: {str(e)}"
        )
