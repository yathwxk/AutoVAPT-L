"""
Target parser module for AutoVAPT-L.
Parses targets from input file and categorizes them as IP addresses or URLs.
"""

import re
import os
import ipaddress
from typing import Dict, List, Tuple, Set
from urllib.parse import urlparse


def is_valid_ip(ip_str: str) -> bool:
    """
    Check if a string is a valid IPv4 or IPv6 address.
    
    Args:
        ip_str: String to check.
        
    Returns:
        bool: True if valid IP address, False otherwise.
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


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
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def parse_targets(file_path: str) -> Dict[str, Set[str]]:
    """
    Parse targets from a file and categorize them as IPs or URLs.
    
    Args:
        file_path: Path to the targets file.
        
    Returns:
        Dict with 'ips' and 'urls' keys containing sets of parsed targets.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file not found: {file_path}")
    
    targets = {
        'ips': set(),
        'urls': set()
    }
    
    with open(file_path, 'r') as f:
        for line in f:
            # Clean the line
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # Check if it's an IP address
            if is_valid_ip(line):
                targets['ips'].add(line)
            # Check if it's a URL
            elif is_valid_url(line):
                targets['urls'].add(line)
            # Try to prepend http:// to see if it's a URL without scheme
            elif is_valid_url(f"http://{line}"):
                targets['urls'].add(f"http://{line}")
            else:
                print(f"Warning: Ignoring invalid target: {line}")
    
    return targets 