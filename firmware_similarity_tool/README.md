# Firmware Similarity Comparison Tool

[English](README.md) | [简体中文](README-zh.md)

## Introduction

The Firmware Similarity Comparison Tool is a multi-module comparison system specifically designed for IoT firmware analysis. It analyzes the similarity between two firmware through multiple dimensions. This tool helps researchers quickly identify similar parts between firmware, analyze potential code reuse, and discover possible vulnerability inheritance relationships.

## Directory Structure

```bash
.
├── README.md
├── comparison_results # Comparison results
├── config.yaml # Configuration file
├── config_manager.py # Configuration file loader
├── logs # Log information from batch comparison processes
├── main.py # Main function
├── modules # Code for different module comparison components
│   ├── __init__.py
│   ├── __pycache__
│   ├── base_module.py
│   ├── binwalk_module.py # Binwalk unpacking module comparison script
│   ├── filesystem_profile_module.py # Filesystem structure module comparison script
│   ├── ghidra_module.py # Ghidra binary-level feature extraction module comparison script
│   ├── interface_exposure_profile_module.py # Exposed communication interface extraction module comparison script
│   ├── param_module.py # Edge binary program parameter call chain module comparison script
│   └── similarity_utils.py # Comprehensive similarity comparison script
├── batch_similarity.py # Batch similarity comparison script
├── solo_compare.py # Overall result processing for batch comparison results
├── exe2sim_cve.csv # CVE-firmware mapping file
└── test_data
    ├── BM-2024-00082
    └── BM-2024-00083
```

## Usage

### Basic Usage

```bash
python main.py <firmware1_path> <firmware2_path> [options]
```

### Command Line Arguments

- `firmware1_path`: First firmware feature path
- `firmware2_path`: Second firmware feature path
- `--firmware1_dir`: First firmware internal directory name (auto-detected if not specified)
- `--firmware2_dir`: Second firmware internal directory name (auto-detected if not specified)
- `--config`: Configuration file path, default is `config.yaml`
- `--output_dir`: Output directory path, default is `comparison_results`
- `--modules`: Modules to enable, comma-separated (overrides configuration file settings)

### Examples

Compare two firmware using all default modules:

```bash
python main.py test_data/BM-2024-00001 test_data/BM-2024-00002
```

Compare two firmware using only specified modules:

```bash
python main.py test_data/BM-2024-00001 test_data/BM-2024-00002 --modules binwalk
```

Specify firmware internal directory names:

```bash
python main.py test_data/BM-2024-00005 test_data/BM-2024-00003 --firmware1_dir "DIR-865L_A1" --firmware2_dir "DIR825B1_FW210NAb02"
```

## Configuration File

The `config.yaml` file contains the global configuration of the tool and specific configurations for each module:

## Output Results

Comparison results are saved in the `comparison_results/<firmware1>_<firmware2>_<timestamp>` directory:

```
comparison_results/BM-2024-00005_BM-2024-00003_20250412_084554/
├── binwalk # Unpacking sequence module comparison results
│   └── binwalk_details.json
├── comparison_summary.json # Overall comparison results
├── filesystem_profile # Filesystem file module comparison results
│   └── filesystem_profile_details.json
├── ghidra # Ghidra module analysis comparison results
│   └── ghidra_details.json
├── interface_exposure # Exposed communication interface module comparison results
│   └── interface_exposure_details.json
└── param # Edge binary program sensitive parameter call chain module comparison results
    └── param_details.json
```

The comparison summary file contains the following information:
```json
{
    "firmware1": "/path/to/firmware1",
    "firmware2": "/path/to/firmware2",
    "firmware1_dir": "firmware1_dirname",
    "firmware2_dir": "firmware2_dirname",
    "timestamp": "20250523_073006",
    "modules": ["binwalk", "interface_exposure", "..."],
    "module_results": {
        "binwalk": {
            "similarity": 0.84755833243988645,
            "details_file": "path/to/binwalk_details.json"
        },
        "interface_exposure": {
            "similarity": 0.91695076776746015,
            "details_file": "path/to/interface_exposure_details.json"
        },
        // ... other module results
    },
    "total_similarity": 0.87
}
```

## Important Notes

- The system assumes that firmware has been preliminarily feature-extracted through the firmware feature extraction tool, with relevant results stored in specific directories under the firmware path
- Some modules depend on specific preprocessing results; please ensure that corresponding analysis data has been generated before running
- Generated result folder names follow the format "{firmware1}_{firmware2}_{timestamp}", allowing clear distinction between different comparison tasks
- Similarity values range from 0.0 to 1.0, with higher values indicating greater similarity 