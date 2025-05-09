#!/usr/bin/env python3
"""
Simplified scanner script for AutoVAPT-L
"""

import os
from autovaptl.utils.parser import parse_targets
from autovaptl.scanners.nmap_scanner import NmapScanner

def main():
    """
    Simplified main function
    """
    # Print a welcome message
    print("AutoVAPT-L: Automated Vulnerability Assessment and Penetration Testing - Lite")
    print("Running in simplified mode\n")
    
    # Define paths and create output directory
    targets_file = "targets.txt"
    output_dir = os.path.join(os.getcwd(), "output")
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize scanner with auto-simulation
    print("Initializing scanner...")
    scanner = NmapScanner(output_dir=os.path.join(output_dir, "nmap"))
    
    # Parse targets
    print(f"Parsing targets from {targets_file}")
    targets = parse_targets(targets_file)
    
    # Display parsed targets
    print(f"Found {len(targets['ips'])} IP targets and {len(targets['urls'])} URL targets")
    
    # Run scans
    print("\nStarting scans...")
    results = []
    
    # Scan IP addresses
    for ip in targets['ips']:
        print(f"Scanning IP: {ip}")
        result = scanner.scan(ip, ["-sV", "-sS", "--top-ports", "100"])
        results.append(result)
    
    # Print results
    print("\nScan Summary:")
    for result in results:
        if 'simulated' in result:
            print(f"- Simulated scan completed for {result['target']}")
        else:
            print(f"- Scan completed for {result['target']}")
        print(f"  Results saved to: {result['output_files']['json']}")
    
    print("\nAll scans completed.")
    
if __name__ == "__main__":
    main() 