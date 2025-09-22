"""
Configuration settings for the Security System application.
"""
from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Database
    database_url: str = "sqlite:///./security.db"
    
    # JWT
    secret_key: str = "your-secret-key-here-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # Blockchain
    polygon_rpc_url: str = "https://polygon-mumbai.g.alchemy.com/v2/your-api-key"
    private_key: str = "your-private-key-for-blockchain-transactions"
    contract_address: str = "your-smart-contract-address"
    
    # External APIs
    virustotal_api_key: str = "your-virustotal-api-key"
    phishtank_api_key: str = "your-phishtank-api-key"
    
    # File Storage
    upload_dir: str = "./uploads"
    max_file_size: int = 10485760  # 10MB
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()

# Ensure upload directory exists
os.makedirs(settings.upload_dir, exist_ok=True)

