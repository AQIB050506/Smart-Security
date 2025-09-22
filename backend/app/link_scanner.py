"""
Link scanning service using VirusTotal and PhishTank APIs.
"""
import requests
import time
from typing import Optional, Dict, Any
import logging
from app.config import settings
from app.schemas import LinkScanResult

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LinkScanner:
    """Service for scanning URLs against threat intelligence databases."""
    
    def __init__(self):
        """Initialize the link scanner with API configurations."""
        self.virustotal_api_key = settings.virustotal_api_key
        self.phishtank_api_key = settings.phishtank_api_key
        self.virustotal_base_url = "https://www.virustotal.com/api/v3"
        self.phishtank_base_url = "https://checkurl.phishtank.com/checkurl/"
    
    def scan_url(self, url: str) -> LinkScanResult:
        """
        Scan a URL against multiple threat intelligence sources.
        
        Args:
            url: The URL to scan
            
        Returns:
            LinkScanResult with scan results
        """
        logger.info(f"Scanning URL: {url}")
        
        # Validate URL format
        if not self._is_valid_url(url):
            return LinkScanResult(
                url=url,
                is_safe=False,
                threat_type="invalid_url",
                confidence=1.0,
                details="Invalid URL format"
            )
        
        # Check PhishTank first (faster)
        phishtank_result = self._check_phishtank(url)
        if not phishtank_result.is_safe:
            return phishtank_result
        
        # Check VirusTotal
        virustotal_result = self._check_virustotal(url)
        if not virustotal_result.is_safe:
            return virustotal_result
        
        # If both checks pass, consider it safe
        return LinkScanResult(
            url=url,
            is_safe=True,
            threat_type=None,
            confidence=0.8,
            details="URL passed all security checks"
        )
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL has valid format."""
        try:
            if not url.startswith(('http://', 'https://')):
                return False
            
            # Basic URL validation
            parts = url.split('/')
            if len(parts) < 3:
                return False
            
            domain = parts[2]
            if '.' not in domain:
                return False
            
            return True
        except:
            return False
    
    def _check_phishtank(self, url: str) -> LinkScanResult:
        """
        Check URL against PhishTank database.
        
        Args:
            url: The URL to check
            
        Returns:
            LinkScanResult with PhishTank results
        """
        try:
            if not self.phishtank_api_key or self.phishtank_api_key == "your-phishtank-api-key":
                logger.warning("PhishTank API key not configured, skipping check")
                return LinkScanResult(
                    url=url,
                    is_safe=True,
                    confidence=0.5,
                    details="PhishTank API not configured"
                )
            
            # PhishTank API call
            response = requests.post(
                self.phishtank_base_url,
                data={
                    'url': url,
                    'format': 'json',
                    'app_key': self.phishtank_api_key
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('results', {}).get('in_database', False):
                    return LinkScanResult(
                        url=url,
                        is_safe=False,
                        threat_type="phishing",
                        confidence=0.9,
                        details="URL found in PhishTank database"
                    )
                else:
                    return LinkScanResult(
                        url=url,
                        is_safe=True,
                        confidence=0.7,
                        details="URL not found in PhishTank database"
                    )
            else:
                logger.warning(f"PhishTank API error: {response.status_code}")
                return LinkScanResult(
                    url=url,
                    is_safe=True,
                    confidence=0.5,
                    details=f"PhishTank API error: {response.status_code}"
                )
                
        except Exception as e:
            logger.error(f"Error checking PhishTank: {e}")
            return LinkScanResult(
                url=url,
                is_safe=True,
                confidence=0.3,
                details=f"PhishTank check error: {str(e)}"
            )
    
    def _check_virustotal(self, url: str) -> LinkScanResult:
        """
        Check URL against VirusTotal database.
        
        Args:
            url: The URL to check
            
        Returns:
            LinkScanResult with VirusTotal results
        """
        try:
            if not self.virustotal_api_key or self.virustotal_api_key == "your-virustotal-api-key":
                logger.warning("VirusTotal API key not configured, skipping check")
                return LinkScanResult(
                    url=url,
                    is_safe=True,
                    confidence=0.5,
                    details="VirusTotal API not configured"
                )
            
            # Submit URL for analysis
            submit_response = requests.post(
                f"{self.virustotal_base_url}/urls",
                headers={
                    'x-apikey': self.virustotal_api_key,
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data=f'url={url}',
                timeout=10
            )
            
            if submit_response.status_code == 200:
                submit_data = submit_response.json()
                url_id = submit_data.get('data', {}).get('id')
                
                if url_id:
                    # Get analysis results
                    analysis_response = requests.get(
                        f"{self.virustotal_base_url}/urls/{url_id}",
                        headers={'x-apikey': self.virustotal_api_key},
                        timeout=10
                    )
                    
                    if analysis_response.status_code == 200:
                        analysis_data = analysis_response.json()
                        stats = analysis_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        
                        if malicious > 0:
                            return LinkScanResult(
                                url=url,
                                is_safe=False,
                                threat_type="malware",
                                confidence=0.9,
                                details=f"URL flagged as malicious by {malicious} engines"
                            )
                        elif suspicious > 0:
                            return LinkScanResult(
                                url=url,
                                is_safe=False,
                                threat_type="suspicious",
                                confidence=0.7,
                                details=f"URL flagged as suspicious by {suspicious} engines"
                            )
                        else:
                            return LinkScanResult(
                                url=url,
                                is_safe=True,
                                confidence=0.8,
                                details="URL not flagged by any VirusTotal engines"
                            )
                    else:
                        logger.warning(f"VirusTotal analysis error: {analysis_response.status_code}")
                        return LinkScanResult(
                            url=url,
                            is_safe=True,
                            confidence=0.5,
                            details=f"VirusTotal analysis error: {analysis_response.status_code}"
                        )
                else:
                    logger.warning("VirusTotal did not return URL ID")
                    return LinkScanResult(
                        url=url,
                        is_safe=True,
                        confidence=0.5,
                        details="VirusTotal submission failed"
                    )
            else:
                logger.warning(f"VirusTotal submission error: {submit_response.status_code}")
                return LinkScanResult(
                    url=url,
                    is_safe=True,
                    confidence=0.5,
                    details=f"VirusTotal submission error: {submit_response.status_code}"
                )
                
        except Exception as e:
            logger.error(f"Error checking VirusTotal: {e}")
            return LinkScanResult(
                url=url,
                is_safe=True,
                confidence=0.3,
                details=f"VirusTotal check error: {str(e)}"
            )
    
    def batch_scan_urls(self, urls: list) -> Dict[str, LinkScanResult]:
        """
        Scan multiple URLs in batch.
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            Dictionary mapping URLs to their scan results
        """
        results = {}
        for url in urls:
            results[url] = self.scan_url(url)
            # Add small delay to avoid rate limiting
            time.sleep(0.5)
        
        return results


# Global link scanner instance
link_scanner = LinkScanner()

