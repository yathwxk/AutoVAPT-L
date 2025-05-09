"""
Nmap scanner implementation with Vulners NSE script support.
"""

import os
import json
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple


class NmapScanner:
    """
    Nmap scanner with Vulners NSE script integration.
    """
    
    def __init__(self, output_dir: str = None, nmap_path: str = "nmap"):
        """
        Initialize the Nmap scanner.
        
        Args:
            output_dir: Directory to save scan results.
            nmap_path: Path to the nmap executable.
        """
        self.nmap_path = nmap_path
        
        # Set output directory
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = os.path.join(os.getcwd(), "output", "nmap")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def _check_nmap_availability(self) -> bool:
        """
        Check if Nmap is available on the system.
        
        Returns:
            bool: True if Nmap is available, False otherwise.
        """
        try:
            process = subprocess.run(
                [self.nmap_path, "-V"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return process.returncode == 0
        except FileNotFoundError:
            return False
    
    def _check_vulners_script(self) -> bool:
        """
        Check if the Vulners NSE script is available.
        
        Returns:
            bool: True if the Vulners script is available, False otherwise.
        """
        try:
            process = subprocess.run(
                [self.nmap_path, "--script-help=vulners"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return "vulners" in process.stdout
        except Exception:
            return False
            
    def scan(self, target: str, options: List[str] = None) -> Dict[str, Any]:
        """
        Perform an Nmap scan with Vulners NSE script on the target.
        
        Args:
            target: Target IP address or hostname to scan.
            options: Additional Nmap options.
            
        Returns:
            Dict containing scan results.
        """
        # Check if Nmap is available
        if not self._check_nmap_availability():
            raise RuntimeError("Nmap is not available. Please install Nmap or check the path.")
            
        # Check if Vulners script is available
        vulners_available = self._check_vulners_script()
        if not vulners_available:
            print("Warning: Vulners NSE script is not available. Vulnerability detection will be limited.")
        
        # Create timestamp and output files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(":", "_").replace("/", "_")
        output_base = os.path.join(self.output_dir, f"{safe_target}_{timestamp}")
        xml_output = f"{output_base}.xml"
        
        # Prepare Nmap command
        cmd = [self.nmap_path, "-oX", xml_output]
        
        # Add Vulners script if available
        if vulners_available:
            cmd.append("--script=vulners")
        
        # Add additional options if provided
        if options:
            cmd.extend(options)
        
        # Add target
        cmd.append(target)
        
        print(f"Running Nmap scan: {' '.join(cmd)}")
        
        # Run the scan
        try:
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if process.returncode != 0:
                print(f"Warning: Nmap scan had non-zero exit code: {process.returncode}")
                print(f"Error output: {process.stderr}")
            
            # Parse the XML output into JSON
            results = self._parse_xml_to_json(xml_output)
            
            # Save the JSON results
            json_output = f"{output_base}.json"
            with open(json_output, 'w') as f:
                json.dump(results, f, indent=2)
                
            return {
                'target': target,
                'timestamp': timestamp,
                'output_files': {
                    'xml': xml_output,
                    'json': json_output
                },
                'results': results
            }
            
        except Exception as e:
            print(f"Error scanning {target}: {str(e)}")
            return {
                'target': target,
                'timestamp': timestamp,
                'error': str(e)
            }
    
    def _parse_xml_to_json(self, xml_file: str) -> Dict[str, Any]:
        """
        Parse Nmap XML output to a JSON-compatible dictionary.
        
        Args:
            xml_file: Path to the XML file.
            
        Returns:
            Dict containing parsed results.
        """
        if not os.path.exists(xml_file):
            return {'error': 'XML file not found'}
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            result = {
                'scan_info': {},
                'hosts': []
            }
            
            # Parse scan info
            if root.find('scaninfo') is not None:
                for info in root.findall('scaninfo'):
                    result['scan_info'][info.get('type')] = {
                        'protocol': info.get('protocol'),
                        'numservices': info.get('numservices')
                    }
            
            # Parse hosts
            for host in root.findall('host'):
                host_data = {
                    'addresses': [],
                    'hostnames': [],
                    'ports': [],
                    'os': []
                }
                
                # Parse addresses
                for addr in host.findall('address'):
                    host_data['addresses'].append({
                        'addr': addr.get('addr'),
                        'addrtype': addr.get('addrtype')
                    })
                
                # Parse hostnames
                hostnames_elem = host.find('hostnames')
                if hostnames_elem is not None:
                    for hostname in hostnames_elem.findall('hostname'):
                        host_data['hostnames'].append({
                            'name': hostname.get('name'),
                            'type': hostname.get('type')
                        })
                
                # Parse ports and services
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        port_data = {
                            'protocol': port.get('protocol'),
                            'portid': port.get('portid'),
                            'state': {},
                            'service': {},
                            'scripts': []
                        }
                        
                        # Parse state
                        state_elem = port.find('state')
                        if state_elem is not None:
                            port_data['state'] = {
                                'state': state_elem.get('state'),
                                'reason': state_elem.get('reason')
                            }
                        
                        # Parse service
                        service_elem = port.find('service')
                        if service_elem is not None:
                            service_data = {
                                'name': service_elem.get('name'),
                                'product': service_elem.get('product'),
                                'version': service_elem.get('version'),
                                'extrainfo': service_elem.get('extrainfo'),
                                'ostype': service_elem.get('ostype')
                            }
                            # Remove None values
                            port_data['service'] = {k: v for k, v in service_data.items() if v is not None}
                        
                        # Parse scripts (including Vulners)
                        for script in port.findall('script'):
                            script_data = {
                                'id': script.get('id'),
                                'output': script.get('output'),
                                'tables': []
                            }
                            
                            # Handle vulners script specially to extract CVEs
                            if script.get('id') == 'vulners':
                                script_data['vulnerabilities'] = []
                                for table in script.findall('table'):
                                    vuln = {
                                        'type': table.get('key'),
                                        'data': {}
                                    }
                                    
                                    for elem in table.findall('elem'):
                                        vuln['data'][elem.get('key')] = elem.text
                                    
                                    script_data['vulnerabilities'].append(vuln)
                            
                            port_data['scripts'].append(script_data)
                        
                        host_data['ports'].append(port_data)
                
                # Parse OS information
                os_elem = host.find('os')
                if os_elem is not None:
                    for match in os_elem.findall('osmatch'):
                        os_data = {
                            'name': match.get('name'),
                            'accuracy': match.get('accuracy')
                        }
                        host_data['os'].append(os_data)
                
                result['hosts'].append(host_data)
            
            return result
            
        except Exception as e:
            return {'error': f'Failed to parse XML: {str(e)}'} 