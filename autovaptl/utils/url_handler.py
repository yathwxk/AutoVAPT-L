"""
URL handler module for AutoVAPT-L.
Provides functions for validating, parsing, and normalizing URLs.
"""

import re
import logging
import socket
from urllib.parse import urlparse, ParseResult
from typing import Dict, List, Set, Tuple, Optional, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('url_handler')


def is_valid_url(url: str) -> bool:
    """
    Check if a string is a valid URL.
    
    Args:
        url: String to check.
        
    Returns:
        bool: True if valid URL, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except ValueError:
        return False


def normalize_url(url: str) -> str:
    """
    Normalize a URL by adding scheme if missing, ensuring trailing slash for base URLs, etc.
    
    Args:
        url: URL to normalize.
        
    Returns:
        str: Normalized URL.
    """
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Parse URL
    parsed = urlparse(url)
    
    # Ensure path has at least a trailing slash if empty
    if not parsed.path:
        url = url + '/'
    
    return url


def extract_urls_from_targets(targets: List[str]) -> Tuple[List[str], List[str]]:
    """
    Extract URLs from a list of targets (which may include IPs, hostnames, and URLs).
    
    Args:
        targets: List of targets (IPs, hostnames, URLs).
        
    Returns:
        Tuple containing (valid_urls, invalid_urls).
    """
    valid_urls = []
    invalid_urls = []
    
    for target in targets:
        # Skip empty targets and comments
        if not target or target.strip().startswith('#'):
            continue
            
        target = target.strip()
        
        # Check if it's already a valid URL
        if is_valid_url(target):
            valid_urls.append(target)
            continue
        
        # Try to normalize and validate
        normalized = normalize_url(target)
        if is_valid_url(normalized):
            valid_urls.append(normalized)
        else:
            invalid_urls.append(target)
    
    return valid_urls, invalid_urls


def categorize_urls(urls: List[str]) -> Dict[str, List[str]]:
    """
    Categorize URLs by port/protocol for different scanning strategies.
    
    Args:
        urls: List of URLs to categorize.
        
    Returns:
        Dict with categories as keys and lists of URLs as values.
    """
    categories = {
        'http_port_80': [],    # Standard HTTP (port 80)
        'https_port_443': [],  # Standard HTTPS (port 443)
        'other_ports': []      # Non-standard ports
    }
    
    for url in urls:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        port = parsed.port
        
        if not port:
            # Default ports if not specified
            port = 443 if scheme == 'https' else 80
        
        if scheme == 'http' and port == 80:
            categories['http_port_80'].append(url)
        elif scheme == 'https' and port == 443:
            categories['https_port_443'].append(url)
        else:
            categories['other_ports'].append(url)
    
    return categories


def is_ip_address(host: str) -> bool:
    """
    Check if a string is an IP address.
    
    Args:
        host: String to check.
        
    Returns:
        bool: True if IP address, False otherwise.
    """
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        return False


def get_url_info(url: str) -> Dict[str, Any]:
    """
    Get detailed information about a URL.
    
    Args:
        url: URL to analyze.
        
    Returns:
        Dict containing URL information.
    """
    parsed = urlparse(url)
    host = parsed.netloc.split(':')[0]
    
    # Determine port
    port = parsed.port
    if not port:
        port = 443 if parsed.scheme == 'https' else 80
    
    return {
        'url': url,
        'scheme': parsed.scheme,
        'host': host,
        'port': port,
        'path': parsed.path or '/',
        'query': parsed.query,
        'is_ip': is_ip_address(host)
    }


def get_port_from_url(url: str) -> int:
    """
    Extract port from URL, or return default port based on scheme.
    
    Args:
        url: URL to extract port from.
        
    Returns:
        Port number.
    """
    parsed = urlparse(url)
    
    # If port is specified in URL, use it
    if parsed.port:
        return parsed.port
    
    # Otherwise, use default port based on scheme
    if parsed.scheme == 'https':
        return 443
    else:  # http
        return 80


def check_url_accessibility(url: str) -> bool:
    """
    Check if the URL is accessible by attempting to resolve DNS and connect to port.
    
    Args:
        url: URL to check.
        
    Returns:
        bool: True if accessible, False otherwise.
    """
    try:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        # Try to resolve hostname to IP
        ip = socket.gethostbyname(parsed.hostname)
        
        # Try to connect to port
        with socket.create_connection((ip, port), timeout=5) as sock:
            return True
    except (socket.error, socket.timeout, socket.gaierror) as e:
        logger.warning(f"URL {url} is not accessible: {str(e)}")
        return False
    except Exception as e:
        logger.warning(f"Error checking URL {url}: {str(e)}")
        return False


def categorize_urls(urls: List[str]) -> Dict[str, List[str]]:
    """
    Categorize URLs by port (80, 443, other).
    
    Args:
        urls: List of URLs to categorize.
        
    Returns:
        Dict with port categories and corresponding URLs.
    """
    categorized = {
        'http_port_80': [],
        'https_port_443': [],
        'other_ports': []
    }
    
    for url in urls:
        # Normalize URL first
        normalized = normalize_url(url)
        parsed = urlparse(normalized)
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        if parsed.scheme == 'http' and port == 80:
            categorized['http_port_80'].append(normalized)
        elif parsed.scheme == 'https' and port == 443:
            categorized['https_port_443'].append(normalized)
        else:
            categorized['other_ports'].append(normalized)
    
    return categorized 