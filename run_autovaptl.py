#!/usr/bin/env python3
"""
AutoVAPT-L: Automated Vulnerability Assessment and Penetration Testing - Lite

A lightweight framework for automated vulnerability scanning and assessment.
"""

import sys
import os
from autovaptl.main import main

if __name__ == "__main__":
    # Add the current directory to the path to ensure imports work correctly
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    # Run the main function
    main() 