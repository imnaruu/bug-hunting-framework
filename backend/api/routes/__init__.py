"""
API Routes Package
"""
from backend.api.routes.health import router as health_router
from backend.api.routes.scan import router as scan_router
from backend.api.routes.recon import router as recon_router
from backend.api.routes.baseline import router as baseline_router
from backend.api.routes.testing import router as testing_router
from backend.api.routes.correlation import router as correlation_router
from backend.api.routes.reports import router as reports_router

__all__ = [
    "health_router",
    "scan_router",
    "recon_router", 
    "baseline_router",
    "testing_router",
    "correlation_router",
    "reports_router"
]
