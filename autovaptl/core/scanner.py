"""
Core scanner module to coordinate scanning activities.
"""

import os
import time
import logging
from typing import Dict, List, Any, Optional, Set
from datetime import datetime

from ..utils.parser import parse_targets
from ..utils.url_handler import extract_urls_from_targets, categorize_urls
from ..scanners.nmap_scanner import NmapScanner
from ..scanners.web_scanners import get_web_scanners
from ..utils.json_handler import save_json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('core_scanner')


class Scanner:
    """
    Main scanner class to coordinate different scanning tools.
    """
    
    def __init__(self, base_output_dir: str = None, nmap_path: str = "nmap", simulate: bool = False):
        """
        Initialize the scanner.
        
        Args:
            base_output_dir: Base directory for output files.
            nmap_path: Path to the nmap executable.
            simulate: Whether to simulate scans instead of actually running them.
        """
        self.simulate = simulate
        
        # Set up output directory with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if base_output_dir:
            self.output_dir = os.path.join(base_output_dir, f"scan_{timestamp}")
        else:
            self.output_dir = os.path.join(os.getcwd(), "output", f"scan_{timestamp}")
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        logger.info(f"Output directory: {self.output_dir}")
        
        # Initialize scanners
        self.nmap_scanner = NmapScanner(
            output_dir=os.path.join(self.output_dir, "nmap"),
            nmap_path=nmap_path,
            simulate=simulate
        )
        
        # Initialize web scanners
        self.web_scanners = get_web_scanners(
            output_dir=os.path.join(self.output_dir, "web"),
            simulate=simulate
        )
        
        # Store scan results
        self.results = {
            "timestamp": timestamp,
            "output_dir": self.output_dir,
            "nmap_results": [],
            "web_results": []
        }
    
    def scan_targets(self, targets_file: str, scan_options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan targets from a file.
        
        Args:
            targets_file: Path to the file containing targets.
            scan_options: Dictionary of scan options.
            
        Returns:
            Dict containing scan results.
        """
        scan_options = scan_options or {}
        
        # Parse targets
        targets = parse_targets(targets_file)
        if not targets:
            logger.error(f"No targets found in {targets_file}")
            return {"error": f"No targets found in {targets_file}"}
        
        # Extract IPs and URLs
        ips = targets.get('ips', [])
        urls, invalid_urls = extract_urls_from_targets(targets.get('urls', []))
        
        # Log target counts
        logger.info(f"Found {len(ips)} IP targets and {len(urls)} URL targets")
        if invalid_urls:
            logger.warning(f"Found {len(invalid_urls)} invalid URLs: {invalid_urls}")
        
        # Store targets in results
        self.results["targets"] = {
            "ips": ips,
            "urls": urls,
            "invalid_urls": invalid_urls
        }
        
        # Scan IPs with Nmap
        if ips and scan_options.get('scan_ips', True):
            logger.info(f"Starting Nmap scan for {len(ips)} IP targets")
            nmap_results = self._scan_with_nmap(ips, scan_options.get('nmap_options', {}))
            self.results["nmap_results"] = nmap_results
            logger.info(f"Completed Nmap scan for {len(ips)} IP targets")
        
        # Scan URLs with web scanners
        if urls and scan_options.get('scan_web', True):
            logger.info(f"Starting web scans for {len(urls)} URL targets")
            web_results = self._scan_web_targets(urls, scan_options.get('web_options', {}))
            self.results["web_results"] = web_results
            logger.info(f"Completed web scans for {len(urls)} URL targets")
        
        # Save final results
        results_file = os.path.join(self.output_dir, "scan_results.json")
        save_json(self.results, results_file)
        logger.info(f"Scan results saved to {results_file}")
        
        return self.results
    
    def _scan_with_nmap(self, targets: List[str], options: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Scan targets with Nmap.
        
        Args:
            targets: List of targets (IPs or hostnames).
            options: Nmap scan options.
            
        Returns:
            List of scan results.
        """
        results = []
        
        # Check if Nmap is available
        if not self.nmap_scanner.check_nmap_available():
            logger.error("Nmap is not available. Skipping Nmap scan.")
            return results
        
        # Scan each target
        for target in targets:
            logger.info(f"Scanning target: {target}")
            
            try:
                # Run the scan
                scan_result = self.nmap_scanner.scan(target, options)
                results.append(scan_result)
                
                # Add a small delay between scans
                if not self.simulate and len(targets) > 1:
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error scanning {target}: {str(e)}")
                results.append({
                    "target": target,
                    "error": str(e),
                    "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S")
                })
        
        return results
    
    def _scan_web_targets(self, urls: List[str], options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan web targets with available web scanners.
        
        Args:
            urls: List of URLs to scan.
            options: Web scan options.
            
        Returns:
            Dict containing scan results for each scanner.
        """
        web_results = {}
        options = options or {}
        
        # Check if we have any web scanners available
        if not self.web_scanners:
            logger.warning("No web scanners available. Skipping web scans.")
            return web_results
        
        # Categorize URLs by protocol/port
        categorized_urls = categorize_urls(urls)
        
        # Log available scanners
        logger.info(f"Available web scanners: {', '.join(self.web_scanners.keys())}")
        
        # Run each available scanner
        for scanner_name, scanner in self.web_scanners.items():
            logger.info(f"Starting {scanner_name} scans")
            scanner_results = []
            
            # Get scanner-specific options
            scanner_options = options.get(scanner_name, {})
            
            # Determine which URLs to scan based on scanner and URL categories
            scan_urls = []
            
            # For Nikto, only scan HTTP/HTTPS on standard ports
            if scanner_name == 'nikto':
                scan_urls.extend(categorized_urls['http_port_80'])
                scan_urls.extend(categorized_urls['https_port_443'])
            # For Wapiti, scan all URLs
            else:
                scan_urls.extend(urls)
            
            # Scan each URL
            for url in scan_urls:
                logger.info(f"Scanning URL with {scanner_name}: {url}")
                
                try:
                    # Run the scan
                    result = scanner.scan(url, scanner_options)
                    scanner_results.append(result)
                    
                    # Add a small delay between scans
                    if not self.simulate and len(scan_urls) > 1:
                        time.sleep(2)
                        
                except Exception as e:
                    logger.error(f"Error scanning {url} with {scanner_name}: {str(e)}")
                    scanner_results.append({
                        "url": url,
                        "scanner": scanner_name,
                        "error": str(e),
                        "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S")
                    })
            
            # Store results for this scanner
            web_results[scanner_name] = scanner_results
            logger.info(f"Completed {scanner_name} scans for {len(scan_urls)} URLs")
        
        return web_results 