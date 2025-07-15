# Firmvulinker

[English](README.md) | [简体中文](README-zh.md)

## 项目简介
Firmvulinker 是一个面向同源物联网嵌入式固件漏洞研究的一站式解决方案，
通过"特征提取 → 相似度计算 → 漏洞迁移"三步骤，帮助研究人员快速定位潜在的漏洞继承关系。
本仓库包含两大核心子项目：

1. **`firmware_analysis_tool`** —— 固件特征提取与分析工具：
   - 支持 Binwalk-Docker 解包、Firmwalker 敏感文件扫描、Ghidra 静态分析、SATC 关键词/参数提取、sdhash 模糊哈希计算等。
   - 结果以结构化 JSON + MySQL 形式保存，便于后续检索或相似度比对。
2. **`firmware_similarity_tool`** —— 多维度固件相似度比较工具：
   - 基于文件系统、二进制函数、接口暴露情况、模糊哈希、参数调用链等多模块综合打分。
   - 支持单对比、批量对比，输出可读的 JSON 汇总报告及各模块详细结果。

两者可以独立运行，也可以串联使用：先批量提取固件特征，再在特征目录上执行相似度比较。

## 相关数据集

本项目的实验数据集存储在独立仓库中：
- **数据集仓库**: [FirmVulLinker-dataset](https://github.com/a101e-lab/FirmVulLinker-dataset)
- **内容说明**: 包含实验中涉及到的groundtruth数据和固件文件
- **数据结构**:
  - `Known_Defective_Firmware/`: 包含已知存在漏洞的固件文件和对应的编号映射
  - `detail_info.csv`: 固件的详细信息以及编号映射表
  - `groundtruth.csv`: 实验的基础数据集
- **字段说明**:
  - BM编号：在FirmEmuHub中对应的可仿真的基础环境的固件编号
  - KDF编号：本次实验中涉及的拥有已知漏洞的固件编号和未知漏洞状态的固件编号
  - vendor：固件的厂商
  - device_type：固件的设备类型
  - hardware_version：固件版本号
  - file_name：固件名

---

## 目录结构
```bash
.
├── README.md
├── firmware_analysis_tool/
│   ├── README.md                  # 子项目说明
│   ├── main.py                    # 分析入口
│   ├── config.yaml                # 全局配置
│   ├── output_json/               # 结果输出目录
│   ├── binwalk_docker_result/     # Binwalk解包结果
│   ├── firmwalker_result/         # Firmwalker扫描结果
│   ├── firmwalker_pro/            # Firmwalker子模块
│   ├── mysql/                     # MySQL配置文件
│   ├── install_sdhash.sh          # sdhash安装脚本
│   └── ...                        # 其他脚本/资源
└── firmware_similarity_tool/
    ├── README.md
    ├── main.py                    # 比对入口
    ├── config.yaml                # 配置文件
    ├── modules/                   # 各维度比较模块代码
    ├── comparison_results/        # 比较结果输出目录
    ├── batch_similarity.py        # 批量相似度比较脚本
    ├── solo_compare.py            # 结果处理脚本
    ├── logs/                      # 日志目录
    └── test_data/                 # 测试数据
```

---

## 环境要求
- **操作系统**：Linux 推荐 Ubuntu 22.04（纯CPU环境即可）
- **Python**：3.8 及以上版本
- **容器化**：Docker 与 docker-compose
- **数据库**：MySQL
- **版本控制**：Git 与 Git LFS（用于管理大文件）
- **额外依赖**：sdhash、Ghidra、ssdeep、pyOpenSSL、pycryptodome

---

## 完整安装步骤

> **推荐使用一键安装脚本**：直接跳转到第9步使用 `firmware_analysis_tool/setup.sh` 脚本进行自动安装。

### 1. 克隆仓库
```bash
# 确保已安装Git LFS
git lfs install

# 克隆仓库（包含LFS文件）
git clone --recursive <repo_url>
cd firmvullinker

# 确保子模块正确clone
git submodule update --init --recursive

# 获取LFS文件
git lfs pull
```

### 2. 安装Python依赖
```bash
pip install ssdeep pyOpenSSL pycryptodome mysql-connector-python argparse
```

### 3. 配置Docker镜像
```bash
# 拉取SATC镜像
docker pull smile0304/satc:latest

# 拉取Binwalk镜像（用于固件解包）
docker pull fitzbc/binwalk 
```

### 4. 安装sdhash
```bash
cd firmware_analysis_tool
chmod +x ./install_sdhash.sh
./install_sdhash.sh
```

### 5. 配置Ghidra
```bash
# 解压Ghidra（文件通过Git LFS管理）
tar -xzvf ghidra_11.0.1_PUBLIC.tar.gz
```

### 6. 配置Firmwalker
```bash
sudo chmod +x firmwalker_pro/firmwalker.sh
```

### 7. 启动MySQL数据库
```bash
cd mysql
docker compose up -d
cd ..
```

### 8. 验证LFS文件
```bash
# 检查LFS文件是否正确下载
git lfs ls-files
```

### 9. 一键安装脚本（推荐）
为了简化安装过程，我们提供了一键安装脚本：

```bash
cd firmware_analysis_tool
chmod +x setup.sh
./setup.sh
```

该脚本会自动执行以下操作：
- 检查系统依赖（Docker、Python 3.8+、pip3、git、Git LFS）
- 安装Python依赖包
- 初始化Git子模块和LFS文件
- 拉取所需的Docker镜像
- 安装sdhash
- 设置Ghidra（如果存在压缩包）
- 启动MySQL数据库
- 验证安装结果

---

## 详细使用方法

### 一、固件特征提取工具（firmware_analysis_tool）

#### 工具简介
这是一个用于嵌入式固件的综合特征提取与分析工具，能够提取固件的架构信息、文件系统类型、操作系统信息，并识别敏感文件、证书和密钥。工具还支持二进制文件分析、模糊哈希计算以及通过SATC和Ghidra进行漏洞分析。

#### 基本使用
```bash
cd firmware_analysis_tool

# 基础固件分析
python main.py -f /path/to/firmware.bin

# 启用SATC深度分析
python main.py -f /path/to/firmware.bin --satc
```

#### 参数说明
- `-f, --firmware_path`：指定要分析的固件文件路径（必需）
- `--satc`：启用SATC进行深度分析（可选，会批量分析`binwalk_docker_result`下的`extract_result`中所有固件经过binwalk提取后的内容）

#### 分析输出结构
```bash
firmware_analysis_tool/
├── binwalk_docker_result/
│   ├── binwalk_log/                 # binwalk分析日志
│   │   ├── 固件名_output.log        # binwalk输出日志
│   │   └── 固件名.json              # binwalk JSON输出
│   └── extract_result/              # 固件解包结果
│       └── _固件名.extracted/       # 解包后的固件内容
│           └── squashfs-root/       # 提取的文件系统
│
├── firmwalker_result/
│   └── 固件名_firmwalker.txt        # firmwalker敏感文件分析结果
│
└── output_json/
    └── 固件名/                      # 每个固件的专属输出目录
        ├── output.json              # 固件分析的主要结果
        ├── func_signature.txt       # 函数签名列表
        ├── func_name.txt            # 函数名列表
        ├── imports.txt              # 导入函数列表
        ├── exports.txt              # 导出函数列表
        ├── symbol_name.txt          # 符号名列表
        ├── string_name.txt          # 字符串名列表
        ├── param_link.json          # 参数调用链信息
        ├── 固件名_all_strings/      # 二进制文件字符串提取
        │   └── all_strings.txt
        ├── keyword_extract_result/   # SATC关键词提取结果
        │   └── detail/
        │       ├── Clustering_result_v2.result
        │       ├── API_detail.result
        │       ├── Prar_detail.result
        │       ├── sorted_clustering.json
        │       ├── binname.list
        │       ├── api_triplets.txt
        │       └── param_triplets.txt
        ├── ghidra_extract_result/    # Ghidra提取结果
        │   └── [各种子目录]/
        │       └── *.result
        └── ghidra_output/            # Ghidra输出
            ├── project/              # Ghidra项目目录
            └── 二进制文件名_ghidra_output.json
```

### 二、固件相似度比较工具（firmware_similarity_tool）

#### 工具介绍
固件相似度比较工具是一个专为物联网固件分析设计的多模块比较系统，通过多个维度分析两个固件的相似性。该工具可以帮助研究人员快速识别固件之间的相似部分，分析潜在的代码重用，以及发现可能的漏洞继承关系。

#### 基本使用
```bash
cd firmware_similarity_tool

# 比较两个固件，使用所有默认模块
python main.py test_data/BM-2024-00001 test_data/BM-2024-00002

# 比较两个固件，只使用指定模块
python main.py test_data/BM-2024-00001 test_data/BM-2024-00002 --modules binwalk,ghidra

# 指定固件内部目录名
python main.py test_data/BM-2024-00005 test_data/BM-2024-00003 --firmware1_dir "DIR-865L_A1" --firmware2_dir "DIR825B1_FW210NAb02"
```

#### 命令行参数
- `固件1路径`：第一个固件特征路径（必需）
- `固件2路径`：第二个固件特征路径（必需）
- `--firmware1_dir`：第一个固件内部目录名（可选，不指定则自动检测）
- `--firmware2_dir`：第二个固件内部目录名（可选，不指定则自动检测）
- `--config`：配置文件路径，默认为`config.yaml`
- `--output_dir`：输出目录路径，默认为`comparison_results`
- `--modules`：要启用的模块，以逗号分隔（覆盖配置文件设置）

#### 可用比较模块
- `binwalk`：解包序列比较模块
- `filesystem_profile`：文件系统文件比较模块
- `interface_exposure`：暴露通信接口比较模块
- `ghidra`：Ghidra静态分析比较模块
- `param`：边界二进制程序敏感参数调用链比较模块

#### 比较结果输出
```bash
comparison_results/固件1_固件2_时间戳/
├── comparison_summary.json         # 总体比较结果
├── binwalk/                        # 解包序列模块比较详细结果
│   └── binwalk_details.json
├── filesystem_profile/             # 文件系统文件模块比较详细结果
│   └── filesystem_profile_details.json
├── interface_exposure/             # 暴露通信接口模块比较详细结果
│   └── interface_exposure_details.json
├── ghidra/                         # ghidra模块分析比较详细结果
│   └── ghidra_details.json
└── param/                          # 参数调用链模块比较详细结果
    └── param_details.json
```

#### 批量比较

##### 批量比较文件结构要求
批量相似度比较功能需要特定的文件结构和配置文件：

```bash
firmware_similarity_tool/
├── batch_similarity.py           # 批量比较脚本
├── exe2sim_cve.csv              # CVE-固件映射文件（必需）
├── origin_data/                 # 固件经过firmware_analysis_tool处理后得到的数据结果目录
│   ├── BM-2024-00001/           # 固件1目录
│   ├── BM-2024-00002/           # 固件2目录
│   └── ...                      # 其他固件目录
├── comparison_results/          # 比较结果输出目录（可通过COMPARISON_RESULTS_DIR环境变量配置）
└── logs_medium_ngram3/          # 日志输出目录（可通过LOGS_DIR环境变量配置）
```

**CVE映射文件格式（exe2sim_cve.csv）**：
```csv
序号,漏洞ID,基准固件,目标固件1,目标固件2,目标固件3,...
1,CVE-2021-1234,BM-2024-00001,BM-2024-00002,BM-2024-00003
2,CVE-2021-5678,BM-2024-00004,BM-2024-00005
```

说明：
- 第一行为标题行（会被跳过）
- 第2列为漏洞ID
- 第3列为基准固件ID
- 第4列及之后为该漏洞影响的其他固件ID
- 同一行中的固件被认为具有相似的漏洞特征

#### 重要注意事项
- 系统假设固件已经通过固件特征提取工具进行了初步特征提取，相关结果存储在固件路径下的特定目录中
- 部分模块依赖特定的预处理结果，请确保运行前已生成相应的分析数据
- 生成的结果文件夹名称格式为"{固件1}_{固件2}_{时间戳}"，可清晰区分不同比较任务
- 相似度值在0.0-1.0之间，值越大表示相似度越高

##### 批量比较使用方法
```bash
# 基本批量相似度比较
python batch_similarity.py

# 指定工作进程数和相似度阈值
python batch_similarity.py --workers 4 --similarity-threshold 0.6

# 指定自定义目录
python batch_similarity.py --output-dir /path/to/results --logs-dir /path/to/logs

# 对批量比较结果进行总体性处理
python solo_compare.py
```

**批量比较参数说明**：
- `--workers`：并行工作进程数量（默认为1）
- `--similarity-threshold`：相似度阈值，大于等于该值判定为相似（默认为0.5）
- `--output-dir`：比较结果输出目录路径
- `--logs-dir`：日志输出目录路径
- `--config`：配置文件路径（默认为config.yaml）

---

## 典型工作流程

### 完整分析流程
```bash
# 0. 首次使用：运行一键安装脚本（推荐）
cd firmware_analysis_tool
chmod +x setup.sh
./setup.sh

# 1. 进入固件分析工具目录
cd firmware_analysis_tool

# 2. 批量分析多个固件
python main.py -f /path/to/firmware1.bin --satc
python main.py -f /path/to/firmware2.bin --satc
python main.py -f /path/to/firmware3.bin --satc

# 3. 进入相似度比较工具目录
cd ../firmware_similarity_tool

# 4. 进行两两比较
python main.py ../firmware_analysis_tool/output_json/firmware1 ../firmware_analysis_tool/output_json/firmware2

# 5. 查看比较结果
cat comparison_results/firmware1_firmware2_*/comparison_summary.json
```

---

## 配置文件说明

### 固件分析工具配置（firmware_analysis_tool/config.yaml）
主要配置数据库连接、Ghidra路径、Docker镜像等参数。

### 相似度比较工具配置（firmware_similarity_tool/config.yaml）
包含各模块的权重设置、阈值配置等参数：
```yaml
modules:
  binwalk:
    enabled: true
    weight: 1.0
  filesystem_profile:
    enabled: true
    weight: 1.0
  # ... 其他模块配置
```

---

## 输出结果示例

### 固件分析结果示例（output.json）
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

### 相似度比较结果示例（comparison_summary.json）
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

## 数据库信息

### 固件分析工具数据库
固件分析结果会存储到MySQL数据库中以便后续查询和比对：
- `firmware_info`表：存储固件的基本信息
- `fuzzy_hashes`表：存储二进制文件的模糊哈希值

---

## 故障排除

### 常见问题
1. **Docker镜像拉取失败**：尝试使用不同的镜像源或检查网络连接
2. **MySQL连接失败**：检查数据库服务状态和配置参数
3. **Ghidra分析失败**：确保Ghidra正确安装且路径配置正确
4. **内存不足**：调整Docker容器内脚本对于内存的限制

