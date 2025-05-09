"""
Core scanner module to coordinate scanning activities.
"""

import os
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

from ..utils.parser import parse_targets
from ..scanners.nmap_scanner import NmapScanner


class Scanner:
    """
    Main scanner class to coordinate different scanning tools.
    """
    
    def __init__(self, base_output_dir: str = None):
        """
        Initialize the scanner.
        
        Args:
            base_output_dir: Base directory for scan outputs.
        """
        # Set base output directory
        if base_output_dir:
            self.base_output_dir = base_output_dir
        else:
            self.base_output_dir = os.path.join(os.getcwd(), "output")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.base_output_dir, exist_ok=True)
        
        # Create a timestamp for this scan session
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = os.path.join(self.base_output_dir, f"scan_{self.timestamp}")
        os.makedirs(self.session_dir, exist_ok=True)
        
        # Initialize scanners
        self.nmap_scanner = NmapScanner(output_dir=os.path.join(self.session_dir, "nmap"))
        
        # Initialize results storage
        self.results = {
            'session_id': self.timestamp,
            'targets': {
                'ips': [],
                'urls': []
            },
            'scan_results': {
                'nmap': []
            }
        }
    
    def scan_targets(self, targets_file: str, nmap_options: List[str] = None) -> Dict[str, Any]:
        """
        Scan targets listed in the provided file.
        
        Args:
            targets_file: Path to the file containing targets.
            nmap_options: Additional options for Nmap scan.
            
        Returns:
            Dict containing scan results.
        """
        # Parse targets from file
        targets = parse_targets(targets_file)
        
        # Update results with parsed targets
        self.results['targets'] = targets
        
        # Get default Nmap options if not provided
        if nmap_options is None:
            nmap_options = ["-sV", "-sS", "-O", "--top-ports", "1000"]
        
        # Scan IP addresses with Nmap
        for ip in targets['ips']:
            print(f"Scanning IP: {ip}")
            result = self.nmap_scanner.scan(ip, nmap_options)
            self.results['scan_results']['nmap'].append(result)
            
            # Small delay to prevent overloading the target
            time.sleep(1)
        
        # Extract IP addresses from URLs and scan them if they're not already scanned
        url_ips = set()
        for url in targets['urls']:
            # Here you would extract the IP from the URL and add to url_ips
            # This requires DNS resolution which is not implemented in this version
            pass
        
        # Scan IPs from URLs that haven't been scanned yet
        for ip in url_ips:
            if ip not in targets['ips']:
                print(f"Scanning IP from URL: {ip}")
                result = self.nmap_scanner.scan(ip, nmap_options)
                self.results['scan_results']['nmap'].append(result)
                
                # Small delay to prevent overloading the target
                time.sleep(1)
        
        # Save the overall results
        self._save_results()
        
        return self.results
    
    def _save_results(self) -> None:
        """
        Save the overall scan results to a JSON file.
        """
        import json
        
        results_file = os.path.join(self.session_dir, "scan_results.json")
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
            
        print(f"Overall scan results saved to: {results_file}") 