# Firmvullinker

[English](README.md) | [简体中文](README-zh.md)

## Project Overview
Firmvullinker is a one-stop solution for vulnerability research in homologous IoT embedded firmware. Through a three-step process of "feature extraction → similarity calculation → vulnerability migration", it helps researchers quickly identify potential vulnerability inheritance relationships.
This repository contains two core sub-projects:

1. **`firmware_analysis_tool`** —— Firmware Feature Extraction and Analysis Tool:
   - Supports Binwalk-Docker unpacking, Firmwalker sensitive file scanning, Ghidra static analysis, SATC keyword/parameter extraction, sdhash fuzzy hash calculation, etc.
   - Results are saved in structured JSON + MySQL format for easy retrieval or similarity comparison.
2. **`firmware_similarity_tool`** —— Multi-dimensional Firmware Similarity Comparison Tool:
   - Comprehensive scoring based on filesystem, binary functions, interface exposure, fuzzy hash, parameter call chains, and other modules.
   - Supports single comparison and batch comparison, outputting readable JSON summary reports and detailed results for each module.

Both tools can run independently or be used in combination: first extract firmware features in batches, then perform similarity comparisons on the feature directories.

---

## Directory Structure
```bash
.
├── README.md
├── firmware_analysis_tool/
│   ├── README.md                  # Sub-project documentation
│   ├── main.py                    # Analysis entry point
│   ├── config.yaml                # Global configuration
│   ├── output_json/               # Result output directory
│   ├── binwalk_docker_result/     # Binwalk unpacking results
│   ├── firmwalker_result/         # Firmwalker scan results
│   ├── firmwalker_pro/            # Firmwalker sub-module
│   ├── mysql/                     # MySQL configuration files
│   ├── install_sdhash.sh          # sdhash installation script
│   └── ...                        # Other scripts/resources
└── firmware_similarity_tool/
    ├── README.md
    ├── main.py                    # Comparison entry point
    ├── config.yaml                # Configuration file
    ├── modules/                   # Module code for various dimension comparisons
    ├── comparison_results/        # Comparison results output directory
    ├── batch_similarity.py        # Batch similarity comparison script
    ├── solo_compare.py            # Result processing script
    ├── logs/                      # Log directory
    └── datas/                     # Test data
```

---

## Environment Requirements
- **Operating System**: Linux, Ubuntu 22.04 recommended (CPU-only environment sufficient)
- **Python**: 3.8 and above
- **Containerization**: Docker and docker-compose
- **Database**: MySQL
- **Additional Dependencies**: sdhash, Ghidra, ssdeep, pyOpenSSL, pycryptodome

---

## Complete Installation Steps

> **Recommended: Use One-click Installation Script**: Skip to step 8 to use the `firmware_analysis_tool/setup.sh` script for automatic installation.

### 1. Clone Repository
```bash
git clone --recursive https://github.com/a101e-lab/FirmVulLinker.git
cd firmvullinker

# Ensure submodules are correctly cloned
git submodule update --init --recursive
```

### 2. Install Python Dependencies
```bash
pip install ssdeep pyOpenSSL pycryptodome mysql-connector-python argparse
```

### 3. Configure Docker Images
```bash
# Pull SATC image
docker pull smile0304/satc:latest

# Pull Binwalk image (for firmware unpacking)
docker pull fitzbc/binwalk 
```

### 4. Install sdhash
```bash
cd firmware_analysis_tool
chmod +x ./install_sdhash.sh
./install_sdhash.sh
```

### 5. Configure Ghidra
```bash
# Extract Ghidra
tar -xzvf ghidra_11.0.1_PUBLIC.tar.gz
```

### 6. Configure Firmwalker
```bash
sudo chmod +x firmwalker_pro/firmwalker.sh
```

### 7. Start MySQL Database
```bash
cd mysql
docker compose up -d
cd ..
```

### 8. One-click Installation Script (Recommended)
To simplify the installation process, we provide a one-click installation script:

```bash
cd firmware_analysis_tool
chmod +x setup.sh
./setup.sh
```

The script will automatically perform the following operations:
- Check system dependencies (Docker, Python 3.8+, pip3, git)
- Install Python dependency packages
- Initialize Git submodules
- Pull required Docker images
- Install sdhash
- Set up Ghidra (if archive exists)
- Start MySQL database
- Verify installation results

---

## Detailed Usage Instructions

### I. Firmware Feature Extraction Tool (firmware_analysis_tool)

#### Tool Overview
This is a comprehensive feature extraction and analysis tool for embedded firmware that can extract firmware architecture information, file system types, operating system information, and identify sensitive files, certificates, and keys. The tool also supports binary file analysis, fuzzy hash computation, and vulnerability analysis through SATC and Ghidra.

#### Basic Usage
```bash
cd firmware_analysis_tool

# Basic firmware analysis
python main.py -f /path/to/firmware.bin

# Enable SATC deep analysis
python main.py -f /path/to/firmware.bin --satc
```

#### Parameter Description
- `-f, --firmware_path`: Specify the firmware file path to analyze (required)
- `--satc`: Enable SATC for deep analysis (optional, will batch analyze all firmware contents extracted by binwalk in `extract_result` under `binwalk_docker_result`)

#### Analysis Output Structure
```bash
result/
├── binwalk_docker_result/
│   ├── binwalk_log/                 # binwalk analysis logs
│   │   ├── firmware_name_output.log # binwalk output log
│   │   └── firmware_name.json       # binwalk JSON output
│   └── extract_result/              # firmware unpacking results
│       └── _firmware_name.extracted/ # unpacked firmware content
│           └── squashfs-root/       # extracted filesystem
│
├── firmwalker_result/
│   └── firmware_name_firmwalker.txt # firmwalker sensitive file analysis results
│
└── output_json/
    └── firmware_name/               # dedicated output directory for each firmware
        ├── output.json              # main firmware analysis results
        ├── func_signature.txt       # function signature list
        ├── func_name.txt            # function name list
        ├── imports.txt              # imported function list
        ├── exports.txt              # exported function list
        ├── symbol_name.txt          # symbol name list
        ├── string_name.txt          # string name list
        ├── param_link.json          # parameter call chain information
        ├── firmware_name_all_strings/ # binary file string extraction
        │   └── all_strings.txt
        ├── keyword_extract_result/   # SATC keyword extraction results
        │   └── detail/
        │       ├── Clustering_result_v2.result
        │       ├── API_detail.result
        │       ├── Prar_detail.result
        │       ├── sorted_clustering.json
        │       ├── binname.list
        │       ├── api_triplets.txt
        │       └── param_triplets.txt
        ├── ghidra_extract_result/    # Ghidra extraction results
        │   └── [various subdirectories]/
        │       └── *.result
        └── ghidra_output/            # Ghidra output
            ├── project/              # Ghidra project directory
            └── binary_name_ghidra_output.json
```

### II. Firmware Similarity Comparison Tool (firmware_similarity_tool)

#### Introduction
The Firmware Similarity Comparison Tool is a multi-module comparison system specifically designed for IoT firmware analysis. It analyzes the similarity between two firmware through multiple dimensions. This tool helps researchers quickly identify similar parts between firmware, analyze potential code reuse, and discover possible vulnerability inheritance relationships.

#### Basic Usage
```bash
cd firmware_similarity_tool

# Compare two firmware using all default modules
python main.py result1/ result2/

# Compare two firmware using only specified modules
python main.py result1/ result2/ --modules binwalk,ghidra

# Specify firmware internal directory names
python main.py result5/ result3/ --firmware1_dir "DIR-865L_A1" --firmware2_dir "DIR825B1_FW210NAb02"
```

#### Command Line Parameters
- `firmware1_path`: First firmware feature path (required)
- `firmware2_path`: Second firmware feature path (required)
- `--firmware1_dir`: First firmware internal directory name (optional, auto-detected if not specified)
- `--firmware2_dir`: Second firmware internal directory name (optional, auto-detected if not specified)
- `--config`: Configuration file path, default is `config.yaml`
- `--output_dir`: Output directory path, default is `comparison_results`
- `--modules`: Modules to enable, comma-separated (overrides configuration file settings)

#### Available Comparison Modules
- `binwalk`: Unpacking sequence comparison module
- `filesystem_profile`: Filesystem file comparison module
- `interface_exposure`: Exposed communication interface comparison module
- `ghidra`: Ghidra static analysis comparison module
- `param`: Edge binary program sensitive parameter call chain comparison module

#### Comparison Result Output
```bash
comparison_results/firmware1_firmware2_timestamp/
├── comparison_summary.json         # Overall comparison results
├── binwalk/                        # Unpacking sequence module detailed comparison results
│   └── binwalk_details.json
├── filesystem_profile/             # Filesystem file module detailed comparison results
│   └── filesystem_profile_details.json
├── interface_exposure/             # Exposed communication interface module detailed comparison results
│   └── interface_exposure_details.json
├── ghidra/                         # ghidra module analysis detailed comparison results
│   └── ghidra_details.json
└── param/                          # Parameter call chain module detailed comparison results
    └── param_details.json
```

#### Batch Comparison

##### Batch Comparison File Structure Requirements
The batch similarity comparison functionality requires specific file structure and configuration files:

```bash
firmware_similarity_tool/
├── batch_similarity.py           # Batch comparison script
├── exe2sim_cve.csv              # CVE-firmware mapping file (required)
├── datas/                 # Data result directory containing firmware processed by firmware_analysis_tool
│   ├── BM-2024-00001/           # Firmware 1 directory
│   ├── BM-2024-00002/           # Firmware 2 directory
│   └── ...                      # Other firmware directories
├── comparison_results/          # Comparison results output directory (configurable via COMPARISON_RESULTS_DIR environment variable)
└── logs_medium_ngram3/          # Log output directory (configurable via LOGS_DIR environment variable)
```

**CVE Mapping File Format (exe2sim_cve.csv)**:
```csv
Index,Vulnerability_ID,Base_Firmware,Target_Firmware1,Target_Firmware2,Target_Firmware3,...
1,CVE-2021-1234,BM-2024-00001,BM-2024-00002,BM-2024-00003
2,CVE-2021-5678,BM-2024-00004,BM-2024-00005
```

Description:
- First row is the header (will be skipped)
- Column 2 contains the vulnerability ID
- Column 3 contains the base firmware ID
- Column 4 and beyond contain other firmware IDs affected by the vulnerability
- Firmware in the same row are considered to have similar vulnerability characteristics

#### Important Notes
- The system assumes that firmware has been preliminarily feature-extracted through the firmware feature extraction tool, with relevant results stored in specific directories under the firmware path
- Some modules depend on specific preprocessing results; please ensure that corresponding analysis data has been generated before running
- Generated result folder names follow the format "{firmware1}_{firmware2}_{timestamp}", allowing clear distinction between different comparison tasks
- Similarity values range from 0.0 to 1.0, with higher values indicating greater similarity

##### Batch Comparison Usage
```bash
# Basic batch similarity comparison
python batch_similarity.py

# Specify number of worker processes and similarity threshold
python batch_similarity.py --workers 4 --similarity-threshold 0.6

# Specify custom directories
python batch_similarity.py --output-dir /path/to/results --logs-dir /path/to/logs

# Overall processing of batch comparison results
python solo_compare.py
```

**Batch Comparison Parameters**:
- `--workers`: Number of parallel worker processes (default: 1)
- `--similarity-threshold`: Similarity threshold, values >= this threshold are considered similar (default: 0.5)
- `--output-dir`: Comparison results output directory path
- `--logs-dir`: Log output directory path
- `--config`: Configuration file path (default: config.yaml)

---

## Typical Workflow

### Complete Analysis Workflow
```bash
# 0. First-time use: Run one-click installation script (recommended)
cd firmware_analysis_tool
chmod +x setup.sh
./setup.sh

# 1. Enter firmware analysis tool directory
cd firmware_analysis_tool

# 2. Batch analyze multiple firmware
python main.py -f /path/to/firmware1.bin --satc
python main.py -f /path/to/firmware2.bin --satc
python main.py -f /path/to/firmware3.bin --satc

# 3. Enter similarity comparison tool directory
cd ../firmware_similarity_tool

# 4. Perform pairwise comparisons
python main.py ../firmware_analysis_tool/output_json/firmware1 ../firmware_analysis_tool/output_json/firmware2

# 5. View comparison results
cat comparison_results/firmware1_firmware2_*/comparison_summary.json
```

---

## Configuration File Description

### Firmware Analysis Tool Configuration (firmware_analysis_tool/config.yaml)
Main configuration for database connections, Ghidra paths, Docker images, and other parameters.

### Similarity Comparison Tool Configuration (firmware_similarity_tool/config.yaml)
Contains weight settings, threshold configurations, and other parameters for each module:
```yaml
modules:
  binwalk:
    enabled: true
    weight: 1.0
  filesystem_profile:
    enabled: true
    weight: 1.0
  # ... other module configurations
```

---

## Output Result Examples

### Firmware Analysis Result Example (output.json)
```json
{
  "firmware_name": "DIR-865L_A1",
  "architecture": "MIPS",
  "os_info": "Linux",
  "filesystem_type": "squashfs",
  "binary_count": 156,
  "sensitive_files": [
    "/etc/passwd",
    "/etc/shadow"
  ],
  "certificates": [...],
  "fuzzy_hash": "..."
}
```

### Similarity Comparison Result Example (comparison_summary.json)
```json
{
  "firmware1": "BM-2024-00005",
  "firmware2": "BM-2024-00003",
  "firmware1_dir": "DIR-865L_A1",
  "firmware2_dir": "DIR825B1_FW210NAb02",
  "timestamp": "20250523_073006",
  "modules": ["binwalk", "filesystem_profile", "interface_exposure", "ghidra", "param"],
  "module_results": {
    "binwalk": {
      "similarity": 0.84755833243988645,
      "details_file": "binwalk/binwalk_details.json"
    },
    "filesystem_profile": {
      "similarity": 0.90,
      "details_file": "filesystem_profile/filesystem_profile_details.json"
    },
    "interface_exposure": {
      "similarity": 0.91695076776746015,
      "details_file": "interface_exposure/interface_exposure_details.json"
    },
    "ghidra": {
      "similarity": 0.88,
      "details_file": "ghidra/ghidra_details.json"
    },
    "param": {
      "similarity": 0.80,
      "details_file": "param/param_details.json"
    }
  },
  "total_similarity": 0.87
}
```

---

## Database Information

### Firmware Analysis Tool Database
Firmware analysis results are stored in a MySQL database for subsequent queries and comparisons:
- `firmware_info` table: stores basic firmware information
- `fuzzy_hashes` table: stores fuzzy hash values of binary files

---

## Troubleshooting

### Common Issues
1. **Docker image pull failure**: Try using different image sources or check network connection
2. **MySQL connection failure**: Check database service status and configuration parameters
3. **Ghidra analysis failure**: Ensure Ghidra is correctly installed and path is properly configured
4. **Insufficient memory**: Adjust Docker container script memory limitations 