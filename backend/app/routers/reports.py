"""
Report routes for submitting and retrieving security reports.
"""
import os
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database import get_db
from app.models import User, Report
from app.schemas import (
    ReportCreate, 
    ReportResponse, 
    ReportListResponse,
    LinkScanResult,
    AIAnalysisResult
)
from app.auth import get_current_active_user
from app.ai_detection import threat_detector
from app.link_scanner import link_scanner
from app.blockchain import blockchain_service
from app.config import settings

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/", response_model=ReportResponse)
async def create_report(
    text: Optional[str] = Form(None),
    link: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Submit a new security report.
    
    Args:
        text: Report text content
        link: URL to scan
        image: Image file to analyze
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        ReportResponse with report details
    """
    # Validate input
    if not text and not link and not image:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one of text, link, or image must be provided"
        )
    
    # Initialize report data
    report_data = {
        "user_id": current_user.id,
        "text": text,
        "link": link,
        "image_path": None
    }
    
    # Handle image upload
    if image:
        if not image.content_type.startswith('image/'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be an image"
            )
        
        # Generate unique filename
        file_extension = os.path.splitext(image.filename)[1] if image.filename else '.jpg'
        filename = f"{uuid.uuid4()}{file_extension}"
        file_path = os.path.join(settings.upload_dir, filename)
        
        # Save image
        with open(file_path, "wb") as buffer:
            content = await image.read()
            if len(content) > settings.max_file_size:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File size exceeds {settings.max_file_size} bytes"
                )
            buffer.write(content)
        
        report_data["image_path"] = file_path
    
    # Create report in database
    report = Report(**report_data)
    db.add(report)
    db.commit()
    db.refresh(report)
    
    # Perform AI analysis
    classification_result = "safe"
    confidence_score = "0.5"
    
    if text:
        text_analysis = threat_detector.analyze_text(text)
        classification_result = text_analysis.classification
        confidence_score = str(text_analysis.confidence)
    
    if image and report.image_path:
        image_analysis = threat_detector.analyze_image(report.image_path)
        # Use the more severe classification
        if image_analysis.classification != "safe" and classification_result == "safe":
            classification_result = image_analysis.classification
            confidence_score = str(image_analysis.confidence)
    
    # Scan link if provided
    if link:
        link_scan = link_scanner.scan_url(link)
        if not link_scan.is_safe:
            classification_result = "scam"  # Override with link scan result
            confidence_score = str(link_scan.confidence)
    
    # Update report with analysis results
    report.classification_result = classification_result
    report.confidence_score = confidence_score
    db.commit()
    
    # Store evidence hash on blockchain
    content_hash = report.get_content_hash()
    blockchain_tx_hash = blockchain_service.store_evidence_hash(content_hash, report.id)
    
    if blockchain_tx_hash:
        report.blockchain_tx_hash = blockchain_tx_hash
        report.is_verified = True
        db.commit()
    
    return report


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Get a specific report by ID.
    
    Args:
        report_id: ID of the report to retrieve
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        ReportResponse with report details
    """
    report = db.query(Report).filter(
        Report.id == report_id,
        Report.user_id == current_user.id
    ).first()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    return report


@router.get("/", response_model=ReportListResponse)
async def get_reports(
    page: int = 1,
    size: int = 10,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Get paginated list of user's reports.
    
    Args:
        page: Page number (1-based)
        size: Number of reports per page
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        ReportListResponse with paginated reports
    """
    # Calculate offset
    offset = (page - 1) * size
    
    # Get reports
    reports = db.query(Report).filter(
        Report.user_id == current_user.id
    ).order_by(desc(Report.created_at)).offset(offset).limit(size).all()
    
    # Get total count
    total = db.query(Report).filter(Report.user_id == current_user.id).count()
    
    return ReportListResponse(
        reports=reports,
        total=total,
        page=page,
        size=size
    )


@router.post("/scan-link", response_model=LinkScanResult)
async def scan_link(
    url: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Scan a URL for threats without creating a report.
    
    Args:
        url: URL to scan
        current_user: Current authenticated user
        
    Returns:
        LinkScanResult with scan results
    """
    return link_scanner.scan_url(url)


@router.post("/analyze-text", response_model=AIAnalysisResult)
async def analyze_text(
    text: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Analyze text content for threats without creating a report.
    
    Args:
        text: Text content to analyze
        current_user: Current authenticated user
        
    Returns:
        AIAnalysisResult with analysis results
    """
    return threat_detector.analyze_text(text)


@router.get("/{report_id}/verify")
async def verify_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Verify a report's blockchain evidence.
    
    Args:
        report_id: ID of the report to verify
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Verification result
    """
    report = db.query(Report).filter(
        Report.id == report_id,
        Report.user_id == current_user.id
    ).first()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    if not report.blockchain_tx_hash:
        return {
            "verified": False,
            "message": "No blockchain transaction found"
        }
    
    # Verify blockchain evidence
    content_hash = report.get_content_hash()
    is_verified = blockchain_service.verify_evidence_hash(
        report.blockchain_tx_hash, 
        content_hash
    )
    
    # Update verification status
    report.is_verified = is_verified
    db.commit()
    
    return {
        "verified": is_verified,
        "transaction_hash": report.blockchain_tx_hash,
        "content_hash": content_hash,
        "message": "Evidence verified on blockchain" if is_verified else "Evidence verification failed"
    }

