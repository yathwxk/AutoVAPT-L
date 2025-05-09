"""
Main entry point for AutoVAPT-L framework.
"""

import os
import sys
import argparse
from typing import List, Optional

from .core.scanner import Scanner


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description='AutoVAPT-L: Automated Vulnerability Assessment and Penetration Testing - Lite',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        '-t', '--targets',
        required=True,
        help='Path to the file containing target IP addresses and URLs (one per line)'
    )
    
    parser.add_argument(
        '-o', '--output-dir',
        default=os.path.join(os.getcwd(), 'output'),
        help='Directory to save scan results'
    )
    
    parser.add_argument(
        '--nmap-options',
        nargs='+',
        default=['-sV', '-sS', '-O', '--top-ports', '1000'],
        help='Additional Nmap scan options (space-separated)'
    )
    
    return parser.parse_args()


def main() -> int:
    """
    Main entry point function.
    
    Returns:
        int: Exit code.
    """
    # Parse command line arguments
    args = parse_arguments()
    
    try:
        # Verify targets file exists
        if not os.path.exists(args.targets):
            print(f"Error: Targets file '{args.targets}' not found.")
            return 1
        
        # Create output directory if it doesn't exist
        os.makedirs(args.output_dir, exist_ok=True)
        
        # Initialize and run the scanner
        scanner = Scanner(base_output_dir=args.output_dir)
        results = scanner.scan_targets(args.targets, args.nmap_options)
        
        print("\nScan Summary:")
        print(f"Session ID: {results['session_id']}")
        print(f"Targets: {len(results['targets']['ips'])} IPs, {len(results['targets']['urls'])} URLs")
        print(f"Scan Results Directory: {scanner.session_dir}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        return 130
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 