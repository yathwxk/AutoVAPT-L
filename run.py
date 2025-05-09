#!/usr/bin/env python3
"""
Simple runner script for AutoVAPT-L
"""

import sys
import os

# Ensure the current directory is in the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

print("Starting AutoVAPT-L runner script")
print(f"Command line arguments: {sys.argv}")

try:
    # Import the main function from autovaptl
    print("Importing main module...")
    from autovaptl.main import main
    
    print("Running main function...")
    if __name__ == "__main__":
        exit_code = main()
        print(f"Main function completed with exit code: {exit_code}")
        sys.exit(exit_code)
except Exception as e:
    print(f"Error occurred: {str(e)}")
    import traceback
    traceback.print_exc()
    sys.exit(1) 