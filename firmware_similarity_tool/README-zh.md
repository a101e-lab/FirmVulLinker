# 固件相似度比较工具

[English](README.md) | [简体中文](README-zh.md)

## 介绍

固件相似度比较工具是一个专为物联网固件分析设计的多模块比较系统，通过多个维度分析两个固件的相似性。该工具可以帮助研究人员快速识别固件之间的相似部分，分析潜在的代码重用，以及发现可能的漏洞继承关系。

## 目录结构

```bash
.
├── README.md
├── comparison_results # 比较后的结果
├── config.yaml # 配置文件
├── config_manager.py # 配置文件载入
├── logs # 存放批量比较过程中的日志信息
├── main.py # 主函数
├── modules # 存放的不同模块比较部分的代码
│   ├── __init__.py
│   ├── __pycache__
│   ├── base_module.py
│   ├── binwalk_module.py # binwalk解包模块比较脚本
│   ├── filesystem_profile_module.py # 文件系统结构模块比较脚本
│   ├── ghidra_module.py # ghidra二进制层次特征提取模块比较脚本
│   ├── interface_exposure_profile_module.py # 暴露通信接口提取模块比较脚本
│   ├── param_module.py # 边界二进制程序参数调用链模块比较脚本
│   └── similarity_utils.py # 综合相似度比较脚本
├── batch_similarity.py # 批量相似度比较脚本
├── solo_compare.py # 针对批量比较后的结果进行总体性结果处理
├── exe2sim_cve.csv # 
└── test_data
    ├── BM-2024-00082
    └── BM-2024-00083
```

## 使用方法

### 基本用法

```bash
python main.py <固件1路径> <固件2路径> [选项]
```

### 命令行参数

- `固件1路径`: 第一个固件特征路径
- `固件2路径`: 第二个固件特征路径
- `--firmware1_dir`: 第一个固件内部目录名（如不指定则自动检测）
- `--firmware2_dir`: 第二个固件内部目录名（如不指定则自动检测）
- `--config`: 配置文件路径，默认为`config.yaml`
- `--output_dir`: 输出目录路径，默认为`comparison_results`
- `--modules`: 要启用的模块，以逗号分隔（覆盖配置文件设置）

### 示例

比较两个固件，使用所有默认模块：

```bash
python main.py test_data/BM-2024-00001 test_data/BM-2024-00002
```

比较两个固件，只使用指定模块：

```bash
python main.py test_data/BM-2024-00001 test_data/BM-2024-00002 --modules binwalk
```

指定固件内部目录名：

```bash
python main.py test_data/BM-2024-00005 test_data/BM-2024-00003 --firmware1_dir "DIR-865L_A1" --firmware2_dir "DIR825B1_FW210NAb02"
```

## 配置文件

`config.yaml`文件包含工具的全局配置和各模块的具体配置：

## 输出结果

比较结果保存在`comparison_results/<固件1>_<固件2>_<时间戳>`目录下：

```
comparison_results/BM-2024-00005_BM-2024-00003_20250412_084554/
├── binwalk # 解包序列模块比较结果
│   └── binwalk_details.json
├── comparison_summary.json # 总体比较结果
├── filesystem_profile # 文件系统文件模块比较结果
│   └── filesystem_profile_details.json
├── ghidra # ghidra模块分析比较结果
│   └── ghidra_details.json
├── interface_exposure # 暴露通信接口模块比较结果
│   └── interface_exposure_details.json
└── param # 边界二进制程序敏感参数调用链模块比较结果
    └── param_details.json
```

比较摘要文件包含以下信息：
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
        // ... 其他模块结果
    },
    "total_similarity": 
}
```

## 注意事项

- 系统假设固件已经通过固件特征提取工具进行了初步特征提取，相关结果存储在固件路径下的特定目录中
- 部分模块依赖特定的预处理结果，请确保运行前已生成相应的分析数据
- 生成的结果文件夹名称格式为"{固件1}_{固件2}_{时间戳}"，可清晰区分不同比较任务
- 相似度值在0.0-1.0之间，值越大表示相似度越高
