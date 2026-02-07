"""
Configuration Management for Bug Hunting Framework
"""
from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    app_name: str = "BugHunter Framework"
    app_version: str = "1.0.0"
    environment: str = "development"
    
    # API Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_reload: bool = True
    
    # Frontend
    frontend_url: str = "http://localhost:3000"
    
    # Security
    secret_key: str = "development-secret-key-change-in-production"
    allowed_origins: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ]
    
    # Database
    database_url: str = "sqlite:///./bug_hunter.db"
    
    # Logging
    log_level: str = "INFO"
    log_file: str = "bug_hunter.log"
    
    # Scope & Safety
    enforce_scope: bool = True
    allow_localhost_testing: bool = False
    
    # Testing Limits
    max_payloads_per_test: int = 10
    request_timeout: int = 30
    max_concurrent_tests: int = 5
    
    # Report Generation
    report_output_dir: str = "./reports"
    report_format: str = "markdown"
    
    # Notifications
    enable_notifications: bool = False
    webhook_url: str = ""
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
