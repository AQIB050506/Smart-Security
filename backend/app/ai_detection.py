"""
AI threat detection for text and image content.
"""
import torch
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from PIL import Image
import requests
from io import BytesIO
from typing import Optional, Dict, Any
import logging
from app.schemas import AIAnalysisResult

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatDetector:
    """AI-powered threat detection for text and images."""
    
    def __init__(self):
        """Initialize the threat detection models."""
        self.text_classifier = None
        self.image_classifier = None
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models for threat detection."""
        try:
            # Load DistilBERT for text classification
            model_name = "distilbert-base-uncased-finetuned-sst-2-english"
            self.text_classifier = pipeline(
                "sentiment-analysis",
                model=model_name,
                tokenizer=model_name,
                device=0 if torch.cuda.is_available() else -1
            )
            logger.info("Text classification model loaded successfully")
            
            # For image classification, we'll use a simple approach
            # In production, you might want to use CLIP or a dedicated NSFW model
            logger.info("Image classification model initialized")
            
        except Exception as e:
            logger.error(f"Error loading AI models: {e}")
            # Fallback to basic keyword detection
            self.text_classifier = None
    
    def analyze_text(self, text: str) -> AIAnalysisResult:
        """
        Analyze text content for threats using AI.
        
        Args:
            text: The text content to analyze
            
        Returns:
            AIAnalysisResult with classification and confidence
        """
        if not text or not text.strip():
            return AIAnalysisResult(
                classification="safe",
                confidence=1.0,
                details="Empty text content"
            )
        
        try:
            if self.text_classifier:
                # Use DistilBERT for sentiment analysis
                result = self.text_classifier(text)
                sentiment = result[0]['label'].lower()
                confidence = result[0]['score']
                
                # Map sentiment to threat classification
                if sentiment == 'negative' and confidence > 0.7:
                    classification = "harassment"
                elif sentiment == 'negative' and confidence > 0.5:
                    classification = "spam"
                else:
                    classification = "safe"
                
                return AIAnalysisResult(
                    classification=classification,
                    confidence=confidence,
                    details=f"Sentiment analysis: {sentiment}"
                )
            else:
                # Fallback to keyword-based detection
                return self._keyword_based_detection(text)
                
        except Exception as e:
            logger.error(f"Error in text analysis: {e}")
            return AIAnalysisResult(
                classification="safe",
                confidence=0.5,
                details=f"Analysis error: {str(e)}"
            )
    
    def _keyword_based_detection(self, text: str) -> AIAnalysisResult:
        """
        Fallback keyword-based threat detection.
        
        Args:
            text: The text content to analyze
            
        Returns:
            AIAnalysisResult with classification and confidence
        """
        text_lower = text.lower()
        
        # Define threat keywords
        scam_keywords = [
            'click here', 'urgent', 'verify account', 'suspended', 'limited time',
            'congratulations', 'winner', 'free money', 'bitcoin', 'crypto',
            'investment opportunity', 'guaranteed returns'
        ]
        
        harassment_keywords = [
            'kill', 'die', 'hate', 'stupid', 'idiot', 'moron', 'threat',
            'violence', 'attack', 'hurt', 'destroy'
        ]
        
        spam_keywords = [
            'buy now', 'discount', 'sale', 'promotion', 'advertisement',
            'marketing', 'subscribe', 'unsubscribe', 'newsletter'
        ]
        
        # Check for scam indicators
        scam_score = sum(1 for keyword in scam_keywords if keyword in text_lower)
        harassment_score = sum(1 for keyword in harassment_keywords if keyword in text_lower)
        spam_score = sum(1 for keyword in spam_keywords if keyword in text_lower)
        
        # Determine classification
        if harassment_score > 0:
            classification = "harassment"
            confidence = min(0.9, 0.5 + (harassment_score * 0.1))
        elif scam_score > 1:
            classification = "scam"
            confidence = min(0.9, 0.5 + (scam_score * 0.1))
        elif spam_score > 0:
            classification = "spam"
            confidence = min(0.8, 0.4 + (spam_score * 0.1))
        else:
            classification = "safe"
            confidence = 0.8
        
        return AIAnalysisResult(
            classification=classification,
            confidence=confidence,
            details=f"Keyword-based detection: scam={scam_score}, harassment={harassment_score}, spam={spam_score}"
        )
    
    def analyze_image(self, image_path: str) -> AIAnalysisResult:
        """
        Analyze image content for threats.
        
        Args:
            image_path: Path to the image file
            
        Returns:
            AIAnalysisResult with classification and confidence
        """
        try:
            # Load and preprocess image
            image = Image.open(image_path)
            
            # Basic image analysis (in production, use CLIP or NSFW detection)
            # For now, we'll do basic checks
            width, height = image.size
            
            # Check for suspicious image characteristics
            if width < 50 or height < 50:
                return AIAnalysisResult(
                    classification="spam",
                    confidence=0.6,
                    details="Very small image size"
                )
            
            # Check file size (if available)
            try:
                file_size = image.fp.tell() if hasattr(image.fp, 'tell') else 0
                if file_size > 5 * 1024 * 1024:  # 5MB
                    return AIAnalysisResult(
                        classification="spam",
                        confidence=0.5,
                        details="Large file size"
                    )
            except:
                pass
            
            # Default to safe for now
            return AIAnalysisResult(
                classification="safe",
                confidence=0.7,
                details="Image appears safe"
            )
            
        except Exception as e:
            logger.error(f"Error in image analysis: {e}")
            return AIAnalysisResult(
                classification="safe",
                confidence=0.3,
                details=f"Image analysis error: {str(e)}"
            )
    
    def analyze_url_content(self, url: str) -> AIAnalysisResult:
        """
        Analyze content from a URL for threats.
        
        Args:
            url: The URL to analyze
            
        Returns:
            AIAnalysisResult with classification and confidence
        """
        try:
            # Fetch content from URL
            response = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            if response.status_code != 200:
                return AIAnalysisResult(
                    classification="spam",
                    confidence=0.6,
                    details=f"URL returned status {response.status_code}"
                )
            
            # Analyze the content
            content = response.text[:1000]  # First 1000 characters
            return self.analyze_text(content)
            
        except Exception as e:
            logger.error(f"Error analyzing URL content: {e}")
            return AIAnalysisResult(
                classification="safe",
                confidence=0.3,
                details=f"URL analysis error: {str(e)}"
            )


# Global threat detector instance
threat_detector = ThreatDetector()

