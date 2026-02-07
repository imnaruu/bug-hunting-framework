"""
FastAPI Main Application Entry Point
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from backend.config import settings
from backend.api.routes import health, recon, baseline, testing, correlation, reports

# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="A professional-grade bug hunting framework based on human-reasoning methodology",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(health.router, prefix="/api", tags=["Health"])
app.include_router(recon.router, prefix="/api/recon", tags=["Reconnaissance"])
app.include_router(baseline.router, prefix="/api/baseline", tags=["Baseline"])
app.include_router(testing.router, prefix="/api/testing", tags=["Testing"])
app.include_router(correlation.router, prefix="/api/correlate", tags=["Correlation"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])

# Mount static frontend files
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")


@app.get("/")
async def serve_frontend():
    """Serve the main frontend page"""
    frontend_index = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), 
        "frontend", 
        "index.html"
    )
    if os.path.exists(frontend_index):
        return FileResponse(frontend_index)
    return {"message": "Bug Hunting Framework API", "version": settings.app_version}


@app.on_event("startup")
async def startup_event():
    """Application startup tasks"""
    print(f"🚀 Starting {settings.app_name} v{settings.app_version}")
    print(f"📍 Environment: {settings.environment}")
    print(f"🔧 API Docs: http://{settings.api_host}:{settings.api_port}/api/docs")
    
    # Create reports directory if it doesn't exist
    os.makedirs(settings.report_output_dir, exist_ok=True)


@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown tasks"""
    print(f"👋 Shutting down {settings.app_name}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
    )
