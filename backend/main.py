"""
FastAPI Main Application Entry Point
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
import os

from backend.config import settings
from backend.api.routes import (
    health_router,
    recon_router,
    baseline_router,
    testing_router,
    correlation_router,
    reports_router,
    scan_router
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    print(f"🚀 Starting {settings.app_name} v{settings.app_version}")
    print(f"📍 Environment: {settings.environment}")
    print(f"🔧 API Docs: http://{settings.api_host}:{settings.api_port}/api/docs")
    
    # Create reports directory if it doesn't exist
    os.makedirs(settings.report_output_dir, exist_ok=True)
    
    yield
    
    # Shutdown
    print(f"👋 Shutting down {settings.app_name}")


# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="A professional-grade bug hunting framework based on human-reasoning methodology",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
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
app.include_router(health_router, prefix="/api")
app.include_router(scan_router, prefix="/api")
app.include_router(recon_router, prefix="/api")
app.include_router(baseline_router, prefix="/api")
app.include_router(testing_router, prefix="/api")
app.include_router(correlation_router, prefix="/api")
app.include_router(reports_router, prefix="/api")

# Mount static frontend files
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")
    # Mount pages directory directly
    pages_path = os.path.join(frontend_path, "pages")
    if os.path.exists(pages_path):
        app.mount("/pages", StaticFiles(directory=pages_path, html=True), name="pages")
    # Mount CSS directory
    css_path = os.path.join(frontend_path, "css")
    if os.path.exists(css_path):
        app.mount("/css", StaticFiles(directory=css_path), name="css")
    # Mount JS directory
    js_path = os.path.join(frontend_path, "js")
    if os.path.exists(js_path):
        app.mount("/js", StaticFiles(directory=js_path), name="js")


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
    )
