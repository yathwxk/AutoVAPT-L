#!/usr/bin/env python3
"""
Setup script for AutoVAPT-L
"""

from setuptools import setup, find_packages
import os

# Get the long description from the README file
with open(os.path.join(os.path.dirname(__file__), 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="autovaptl",
    version="0.1.0",
    description="Automated Vulnerability Assessment and Penetration Testing - Lite",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourusername/AutoVAPT-L",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[],  # No direct dependencies other than Python standard library
    entry_points={
        "console_scripts": [
            "autovaptl=autovaptl.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
    ],
) 