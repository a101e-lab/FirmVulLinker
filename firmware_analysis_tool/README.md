# Embedded Firmware Feature Extraction and Analysis Tool

[English](README.md) | [简体中文](README-zh.md)

## Tool Overview

This is a comprehensive feature extraction and analysis tool for embedded firmware that can extract firmware architecture information, file system types, operating system information, and identify sensitive files, certificates, and keys. The tool also supports binary file analysis, fuzzy hash computation, and vulnerability analysis through SATC and Ghidra.

## Environment Requirements

### Required Tools
- Docker
- Python 3.8+
- Git and Git LFS (for managing large files like Ghidra)
- sdhash
- MySQL Database
- Ghidra (please compile in advance)

### Required Python Libraries
```bash
pip install ssdeep pyOpenSSL pycryptodome mysql-connector-python argparse
```

### Required Submodule Cloning
```bash
# Ensure Git LFS is installed
git lfs install

# Execute the following commands in the root directory to clone submodule contents (ensure GitHub connectivity)
git submodule update --init --recursive

# Pull LFS-managed large files
git lfs pull

sudo chmod +x firmwalker_pro/firmwalker.sh
```

## Installation Steps

```bash
# 1. Pull required Docker images

# Pull SATC image
docker pull smile0304/satc:latest

# Pull Binwalk image (for firmware unpacking)
docker pull fitzbc/binwalk 

# 2. Install sdhash

chmod +x ./install_sdhash.sh

./install_sdhash.sh

# 3. Install Ghidra (file managed by Git LFS)
tar -xzvf ghidra_11.0.1_PUBLIC.tar.gz

# 4. Configure and start MySQL database

# Enter MySQL configuration directory

cd mysql

# Start MySQL container
docker compose up -d

# 5. Verify LFS files
git lfs ls-files
```

### Provided One-click Installation Script

```bash
chmod +x setup.sh

./setup.sh
```

## Usage

### Basic Usage

```bash
python main.py -f /path/to/firmware.bin # Analyze firmware file
```

### Enable SATC Analysis (will batch analyze all firmware contents extracted by binwalk in `extract_result` under `binwalk_docker_result`)

```bash
python main.py -f /path/to/firmware.bin --satc # Use --satc parameter to invoke SATC for deep analysis (if encountering memory issues, modify memory limits inside the SATC container)
```

### Parameter Description
- `-f, --firmware_path`: Specify the firmware file path to analyze (required)
- `--satc`: Enable SATC for analysis (optional)

## Output Results

```bash
├── binwalk_docker_result/
│   ├── binwalk_log/                 # binwalk analysis logs
│   │   ├── firmware_name_output.log # binwalk output log
│   │   └── firmware_name.json       # binwalk JSON output
│   └── extract_result/              # firmware unpacking results
│       └── _firmware_name.extracted/ # unpacked firmware contents
│           └── squashfs-root/       # extracted file system
│
├── firmwalker_result/
│   └── firmware_name_firmwalker.txt # firmwalker sensitive file analysis results
│
├── output_json/
│   ├── firmware_name/               # dedicated output directory for each firmware
│   │   └── firmware_name_all_strings # all strings extracted from binary files
│   │   │   └──all_strings.txt 
│   │   ├── output.json               # main firmware analysis results
│   │   ├── func_signature.txt        # function signature list
│   │   ├── func_name.txt             # function name list
│   │   ├── imports.txt               # imported function list
│   │   ├── exports.txt               # exported function list
│   │   ├── symbol_name.txt           # symbol name list
│   │   ├── string_name.txt           # string name list
│   │   ├── param_link.json           # parameter call chain information
│   │   │
│   │   ├── keyword_extract_result/   # SATC keyword extraction results
│   │   │   └── detail/
│   │   │       ├── Clustering_result_v2.result  # clustering results
│   │   │       ├── API_detail.result            # API details
│   │   │       ├── Prar_detail.result           # parameter details
│   │   │       ├── sorted_clustering.json       # sorted clustering results
│   │   │       ├── binname.list                 # binary file name list
│   │   │       ├── api_triplets.txt             # API triplets (API name, text file, binary file)
│   │   │       └── param_triplets.txt           # parameter triplets (parameter name, text file, binary file)
│   │   │
│   │   ├── ghidra_extract_result/    # Ghidra extraction results
│   │   │   └── [various subdirectories]/
│   │   │       └── *.result          # Ghidra analysis result files
│   │   │
│   │   └── ghidra_output/            # Ghidra output
│   │       ├── project/              # Ghidra project directory
│   │       └── binary_name_ghidra_output.json  # Ghidra analysis output
```

## Database Information

Firmware analysis results are stored in a MySQL database for subsequent queries and comparisons:
- `firmware_info` table: stores basic firmware information
- `fuzzy_hashes` table: stores fuzzy hash values of binary files