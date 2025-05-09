"""
Web scanners implementation for AutoVAPT-L.
Supports Wapiti and Nikto scanning for web applications.
"""

import os
import json
import subprocess
import logging
import urllib.parse
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Union
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('web_scanners')


class WebScanner:
    """
    Base class for web application scanners.
    """
    
    def __init__(self, output_dir: str = None, simulate: bool = False):
        """
        Initialize the web scanner.
        
        Args:
            output_dir: Directory to save scan results.
            simulate: Whether to run in simulation mode (don't actually run scans).
        """
        self.output_dir = output_dir or os.path.join(os.getcwd(), 'output', 'web')
        self.simulate = simulate
        os.makedirs(self.output_dir, exist_ok=True)
        
    def is_available(self) -> bool:
        """
        Check if the scanner is available on the system.
        
        Returns:
            bool: True if scanner is available, False otherwise.
        """
        raise NotImplementedError("Subclasses must implement is_available()")
    
    def scan(self, url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan a URL with the web scanner.
        
        Args:
            url: URL to scan.
            options: Additional options for the scanner.
            
        Returns:
            Dict containing scan results.
        """
        raise NotImplementedError("Subclasses must implement scan()")
    
    def _parse_results(self, output: str) -> Dict[str, Any]:
        """
        Parse scanner output into a structured format.
        
        Args:
            output: Scanner output as string.
            
        Returns:
            Dict containing parsed results.
        """
        raise NotImplementedError("Subclasses must implement _parse_results()")


class WapitiScanner(WebScanner):
    """
    Wapiti web vulnerability scanner implementation.
    """
    
    def __init__(self, output_dir: str = None, simulate: bool = False):
        """
        Initialize the Wapiti scanner.
        
        Args:
            output_dir: Directory to save scan results.
            simulate: Whether to run in simulation mode.
        """
        super().__init__(output_dir, simulate)
        self.tool_name = "wapiti"
        self.output_dir = os.path.join(self.output_dir, "wapiti")
        os.makedirs(self.output_dir, exist_ok=True)
    
    def is_available(self) -> bool:
        """
        Check if Wapiti is available on the system.
        
        Returns:
            bool: True if Wapiti is available, False otherwise.
        """
        try:
            result = subprocess.run(
                ["wapiti", "--version"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.warning("Wapiti not found on the system.")
            return False
    
    def scan(self, url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan a URL with Wapiti.
        
        Args:
            url: URL to scan.
            options: Additional options for Wapiti.
            
        Returns:
            Dict containing scan results.
        """
        options = options or {}
        
        # Parse the hostname from the URL for the output filename
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.netloc.split(':')[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f"{hostname}_{timestamp}")
        
        # Build Wapiti command
        cmd = ["wapiti", "-u", url, "-f", "json", "-o", output_file]
        
        # Add additional options
        modules = options.get('modules')
        if modules:
            cmd.extend(["-m", modules])
        
        scope = options.get('scope', 'folder')
        cmd.extend(["--scope", scope])
        
        # Set scan depth
        depth = options.get('depth', 2)
        cmd.extend(["-d", str(depth)])
        
        # Set timeout
        timeout = options.get('timeout', 30)
        cmd.extend(["-t", str(timeout)])
        
        # Log the command
        logger.info(f"Running Wapiti scan: {' '.join(cmd)}")
        
        if self.simulate:
            logger.info("Simulation mode: not actually running Wapiti.")
            return {
                "status": "simulated",
                "command": " ".join(cmd),
                "url": url,
                "timestamp": timestamp
            }
        
        try:
            # Run Wapiti
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=options.get('process_timeout', 3600)  # Default 1 hour timeout
            )
            
            # Check if output file was created
            json_output_file = f"{output_file}.json"
            if os.path.exists(json_output_file):
                with open(json_output_file, 'r') as f:
                    results = json.load(f)
                
                return {
                    "status": "success",
                    "command": " ".join(cmd),
                    "url": url,
                    "timestamp": timestamp,
                    "return_code": process.returncode,
                    "stdout": process.stdout,
                    "stderr": process.stderr,
                    "results": results,
                    "output_file": json_output_file
                }
            else:
                logger.error(f"Wapiti scan failed: output file {json_output_file} not created.")
                return {
                    "status": "error",
                    "command": " ".join(cmd),
                    "url": url,
                    "timestamp": timestamp,
                    "return_code": process.returncode,
                    "stdout": process.stdout,
                    "stderr": process.stderr,
                    "error": "Output file not created"
                }
                
        except subprocess.TimeoutExpired:
            logger.error(f"Wapiti scan timed out for URL: {url}")
            return {
                "status": "timeout",
                "command": " ".join(cmd),
                "url": url,
                "timestamp": timestamp,
                "error": "Process timed out"
            }
        except Exception as e:
            logger.error(f"Error running Wapiti scan: {str(e)}")
            return {
                "status": "error",
                "command": " ".join(cmd),
                "url": url,
                "timestamp": timestamp,
                "error": str(e)
            }


class NiktoScanner(WebScanner):
    """
    Nikto web vulnerability scanner implementation.
    """
    
    def __init__(self, output_dir: str = None, simulate: bool = False, nikto_path: str = None):
        """
        Initialize the Nikto scanner.
        
        Args:
            output_dir: Directory to save scan results.
            simulate: Whether to run in simulation mode.
            nikto_path: Path to nikto.pl if not in system PATH.
        """
        super().__init__(output_dir, simulate)
        self.tool_name = "nikto"
        self.output_dir = os.path.join(self.output_dir, "nikto")
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Try to find Nikto if path not provided
        self.nikto_path = nikto_path
        if not self.nikto_path:
            # Check common locations
            possible_paths = [
                "nikto",  # If in PATH
                "nikto.pl",
                os.path.join("C:", "Users", "yathw", "nikto", "program", "nikto.pl"),
                os.path.join(os.path.expanduser("~"), "nikto", "program", "nikto.pl"),
                os.path.join("C:", "nikto", "program", "nikto.pl"),
                os.path.join("D:", "nikto", "program", "nikto.pl")
            ]
            
            for path in possible_paths:
                if self._check_nikto_path(path):
                    self.nikto_path = path
                    break
    
    def _check_nikto_path(self, path: str) -> bool:
        """
        Check if the given path points to a valid Nikto installation.
        
        Args:
            path: Path to check.
            
        Returns:
            bool: True if path is valid, False otherwise.
        """
        try:
            # For direct command (if nikto is in PATH)
            if path == "nikto":
                result = subprocess.run(
                    ["nikto", "-Version"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=5
                )
                return result.returncode == 0
            else:
                # For Perl script
                perl_path = self._get_perl_path()
                if not perl_path:
                    return False
                
                result = subprocess.run(
                    [perl_path, path, "-Version"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=5
                )
                return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def _get_perl_path(self) -> Optional[str]:
        """
        Find the Perl interpreter path.
        
        Returns:
            str: Path to perl executable or None if not found.
        """
        try:
            # Check if perl is in PATH
            result = subprocess.run(
                ["perl", "-v"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return "perl"
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        # Check common Perl installation locations
        possible_paths = [
            os.path.join("C:", "Strawberry", "perl", "bin", "perl.exe"),
            os.path.join("C:", "Perl", "bin", "perl.exe"),
            os.path.join("C:", "Program Files", "Perl", "bin", "perl.exe"),
            os.path.join("C:", "Program Files (x86)", "Perl", "bin", "perl.exe")
        ]
        
        for path in possible_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path
        
        return None
    
    def is_available(self) -> bool:
        """
        Check if Nikto is available on the system.
        
        Returns:
            bool: True if Nikto is available, False otherwise.
        """
        if not self.nikto_path:
            logger.warning("Nikto path not found.")
            return False
        
        perl_path = self._get_perl_path()
        if not perl_path:
            logger.warning("Perl interpreter not found.")
            return False
        
        try:
            if self.nikto_path == "nikto":
                cmd = ["nikto", "-Version"]
            else:
                cmd = [perl_path, self.nikto_path, "-Version"]
                
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                logger.info(f"Nikto found: {result.stdout.strip()}")
                return True
            else:
                logger.warning(f"Nikto test failed: {result.stderr}")
                return False
        except Exception as e:
            logger.warning(f"Error checking Nikto availability: {str(e)}")
            return False
    
    def scan(self, url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan a URL with Nikto.
        
        Args:
            url: URL to scan.
            options: Additional options for Nikto.
            
        Returns:
            Dict containing scan results.
        """
        options = options or {}
        
        if not self.is_available():
            return {
                "status": "error",
                "url": url,
                "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
                "error": "Nikto not available"
            }
        
        # Parse the hostname from the URL for the output filename
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.netloc.split(':')[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f"{hostname}_{timestamp}")
        
        # Build Nikto command
        perl_path = self._get_perl_path()
        
        if self.nikto_path == "nikto":
            cmd = ["nikto", "-h", url, "-o", f"{output_file}.json", "-Format", "json"]
        else:
            cmd = [perl_path, self.nikto_path, "-h", url, "-o", f"{output_file}.json", "-Format", "json"]
        
        # Add additional options
        if options.get('tuning'):
            cmd.extend(["-Tuning", options['tuning']])
        
        if options.get('plugins'):
            cmd.extend(["-Plugins", options['plugins']])
        
        if options.get('port'):
            cmd.extend(["-p", str(options['port'])])
        
        # Log the command
        logger.info(f"Running Nikto scan: {' '.join(cmd)}")
        
        if self.simulate:
            logger.info("Simulation mode: not actually running Nikto.")
            return {
                "status": "simulated",
                "command": " ".join(cmd),
                "url": url,
                "timestamp": timestamp
            }
        
        try:
            # Run Nikto
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=options.get('process_timeout', 3600)  # Default 1 hour timeout
            )
            
            # Also save the raw output
            with open(f"{output_file}.txt", 'w') as f:
                f.write(process.stdout)
            
            # Check if JSON output file was created
            json_output_file = f"{output_file}.json"
            if os.path.exists(json_output_file):
                try:
                    with open(json_output_file, 'r') as f:
                        results = json.load(f)
                except json.JSONDecodeError:
                    # If JSON is invalid, read as text
                    with open(json_output_file, 'r') as f:
                        results = {"raw_output": f.read()}
                
                return {
                    "status": "success",
                    "command": " ".join(cmd),
                    "url": url,
                    "timestamp": timestamp,
                    "return_code": process.returncode,
                    "stdout": process.stdout,
                    "stderr": process.stderr,
                    "results": results,
                    "output_file": json_output_file
                }
            else:
                logger.warning(f"Nikto JSON output file not created. Using stdout.")
                return {
                    "status": "partial_success",
                    "command": " ".join(cmd),
                    "url": url,
                    "timestamp": timestamp,
                    "return_code": process.returncode,
                    "stdout": process.stdout,
                    "stderr": process.stderr,
                    "results": {"raw_output": process.stdout},
                    "output_file": f"{output_file}.txt"
                }
                
        except subprocess.TimeoutExpired:
            logger.error(f"Nikto scan timed out for URL: {url}")
            return {
                "status": "timeout",
                "command": " ".join(cmd),
                "url": url,
                "timestamp": timestamp,
                "error": "Process timed out"
            }
        except Exception as e:
            logger.error(f"Error running Nikto scan: {str(e)}")
            return {
                "status": "error",
                "command": " ".join(cmd),
                "url": url,
                "timestamp": timestamp,
                "error": str(e)
            }


def get_web_scanners(output_dir: str = None, simulate: bool = False) -> Dict[str, WebScanner]:
    """
    Get all available web scanners.
    
    Args:
        output_dir: Directory to save scan results.
        simulate: Whether to run in simulation mode.
        
    Returns:
        Dict of scanner name to scanner instance.
    """
    scanners = {}
    
    wapiti = WapitiScanner(output_dir, simulate)
    if wapiti.is_available():
        scanners['wapiti'] = wapiti
    else:
        logger.warning("Wapiti scanner not available.")
    
    nikto = NiktoScanner(output_dir, simulate)
    if nikto.is_available():
        scanners['nikto'] = nikto
    else:
        logger.warning("Nikto scanner not available.")
    
    return scanners 