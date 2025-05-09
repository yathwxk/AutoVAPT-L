"""
Main entry point for AutoVAPT-L framework.
"""

import os
import sys
import json
import argparse
import traceback
import logging
from typing import List, Optional, Dict, Any, Set

from .core.scanner import Scanner
from .utils.parser import parse_targets
from .utils.url_handler import extract_urls_from_targets, categorize_urls

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('autovaptl')

# Helper function to recursively convert sets to lists for JSON serialization
def convert_sets_to_lists(obj):
    if isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, dict):
        return {k: convert_sets_to_lists(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_sets_to_lists(v) for v in obj]
    else:
        return obj


def setup_arg_parser() -> argparse.ArgumentParser:
    """
    Set up command line argument parser.
    
    Returns:
        Configured argument parser.
    """
    parser = argparse.ArgumentParser(description='AutoVAPT-L: Automated Vulnerability Assessment and Penetration Testing Lite')
    
    # Target specification
    parser.add_argument('-t', '--targets', dest='targets_file', required=True,
                        help='Path to file containing targets (IPs, URLs)')
    
    # Output options
    parser.add_argument('-o', '--output-dir', dest='output_dir', default=None,
                        help='Directory to store output files')
    
    # Scan options
    parser.add_argument('--nmap-path', dest='nmap_path', default='nmap',
                        help='Path to nmap executable')
    parser.add_argument('--nmap-options', dest='nmap_options', default=None,
                        help='Comma-separated list of Nmap options (e.g., "-sV,-sS,-O")')
    parser.add_argument('--no-nmap', dest='no_nmap', action='store_true',
                        help='Skip Nmap scanning')
    
    # Web scanning options
    parser.add_argument('--no-web', dest='no_web', action='store_true',
                        help='Skip web scanning')
    parser.add_argument('--wapiti-options', dest='wapiti_options', default=None,
                        help='JSON-formatted Wapiti options (e.g., \'{"modules":"xss,sql","scope":"folder"}\')')
    parser.add_argument('--nikto-options', dest='nikto_options', default=None,
                        help='JSON-formatted Nikto options (e.g., \'{"tuning":"123"}\')')
    
    # Other options
    parser.add_argument('--simulate', action='store_true',
                        help='Simulate scans without actually running them')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    
    return parser


def parse_options(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Parse command line arguments into scan options.
    
    Args:
        args: Command line arguments.
        
    Returns:
        Dict containing scan options.
    """
    options = {
        'scan_ips': not args.no_nmap,
        'scan_web': not args.no_web,
        'nmap_options': {},
        'web_options': {
            'wapiti': {},
            'nikto': {}
        }
    }
    
    # Parse Nmap options
    if args.nmap_options:
        nmap_args = args.nmap_options.split(',')
        options['nmap_options'] = {
            'args': nmap_args,
            'scripts': ['vulners']  # Always include vulners script for CVE detection
        }
    else:
        # Default Nmap options
        options['nmap_options'] = {
            'args': ['-sV', '-sS', '-O', '--top-ports', '1000'],
            'scripts': ['vulners']
        }
    
    # Parse Wapiti options
    if args.wapiti_options:
        try:
            wapiti_opts = json.loads(args.wapiti_options)
            options['web_options']['wapiti'] = wapiti_opts
        except json.JSONDecodeError:
            logger.warning(f"Invalid Wapiti options JSON: {args.wapiti_options}")
    else:
        # Default Wapiti options
        options['web_options']['wapiti'] = {
            'modules': 'xss,sql,exec,file,upload,ssrf,redirect,xxe,crlf,htaccess',
            'scope': 'folder',
            'depth': 2
        }
    
    # Parse Nikto options
    if args.nikto_options:
        try:
            nikto_opts = json.loads(args.nikto_options)
            options['web_options']['nikto'] = nikto_opts
        except json.JSONDecodeError:
            logger.warning(f"Invalid Nikto options JSON: {args.nikto_options}")
    else:
        # Default Nikto options
        options['web_options']['nikto'] = {
            'tuning': '1234567890abcde',  # All checks
        }
    
    return options


def main():
    """
    Main entry point for the AutoVAPT-L framework.
    """
    # Set up argument parser
    parser = setup_arg_parser()
    args = parser.parse_args()
    
    # Configure logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    try:
        logger.info("Starting AutoVAPT-L framework")
        
        # Check if targets file exists
        if not os.path.isfile(args.targets_file):
            logger.error(f"Targets file not found: {args.targets_file}")
            sys.exit(1)
        
        # Parse scan options
        scan_options = parse_options(args)
        
        # Initialize scanner
        scanner = Scanner(
            base_output_dir=args.output_dir,
            nmap_path=args.nmap_path,
            simulate=args.simulate
        )
        
        # Run the scan
        logger.info(f"Scanning targets from: {args.targets_file}")
        results = scanner.scan_targets(args.targets_file, scan_options)
        
        logger.info("Scan completed successfully")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        if args.debug:
            logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main() 