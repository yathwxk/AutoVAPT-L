# AutoVAPT-L

**Automated Vulnerability Assessment and Penetration Testing - Lite**

AutoVAPT-L is a modular Python framework for performing remote vulnerability assessments using open-source tools such as Nmap, Nikto, SQLmap, and Wapiti.

## Phase 1 Features

- Parse user input from `targets.txt` to extract IP addresses and web URLs
- Run Nmap with the Vulners NSE script for vulnerability detection
- Save scan results in structured formats (XML and JSON)
- Automated execution using Python's `subprocess` module
- Remote scanning with no installations or agents on target systems
- Modular code with clean separation of logic and outputs

## Requirements

- Python 3.7+
- Nmap with Vulners NSE script installed (`nmap --script-updatedb` to update scripts)

## Installation

### Option 1: Install from source

```bash
# Clone the repository
git clone https://github.com/yourusername/AutoVAPT-L.git
cd AutoVAPT-L

# Install the package
pip install -e .
```

### Option 2: Manual execution

```bash
# Clone the repository
git clone https://github.com/yourusername/AutoVAPT-L.git
cd AutoVAPT-L

# Run directly
python -m autovaptl.main -t targets.txt
```

## Usage

1. Create a `targets.txt` file with your target IP addresses and URLs (one per line)
2. Run the scanner:

```bash
# If installed as a package
autovaptl -t targets.txt -o output_directory

# Or directly
python -m autovaptl.main -t targets.txt -o output_directory
```

## Command Line Options

```
usage: autovaptl [-h] -t TARGETS [-o OUTPUT_DIR] [--nmap-options NMAP_OPTIONS [NMAP_OPTIONS ...]]

AutoVAPT-L: Automated Vulnerability Assessment and Penetration Testing - Lite

optional arguments:
  -h, --help            show this help message and exit
  -t TARGETS, --targets TARGETS
                        Path to the file containing target IP addresses and URLs (one per line) (default: None)
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Directory to save scan results (default: current_dir/output)
  --nmap-options NMAP_OPTIONS [NMAP_OPTIONS ...]
                        Additional Nmap scan options (space-separated) (default: ['-sV', '-sS', '-O', '--top-ports', '1000'])
```

## Output Structure

Results are saved in a structured folder hierarchy:

```
output/
└── scan_YYYYMMDD_HHMMSS/
    ├── scan_results.json      # Overall scan summary
    └── nmap/
        ├── target1_YYYYMMDD_HHMMSS.xml  # Nmap XML output
        ├── target1_YYYYMMDD_HHMMSS.json # Parsed Nmap results
        ├── target2_YYYYMMDD_HHMMSS.xml
        └── target2_YYYYMMDD_HHMMSS.json
```

## Future Development

Phase 2 will include:
- Integration with Nikto and Wapiti for web application scanning
- Enhanced reporting capabilities
- More vulnerability detection plugins

## License

MIT License 