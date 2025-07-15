# 嵌入式固件特征提取分析工具

[English](README.md) | [简体中文](README-zh.md)

## 工具简介

这是一个用于嵌入式固件的综合特征提取与分析工具，能够提取固件的架构信息、文件系统类型、操作系统信息，并识别敏感文件、证书和密钥。工具还支持二进制文件分析、模糊哈希计算以及通过SATC和Ghidra进行漏洞分析。

## 环境要求

### 依赖工具
- Docker
- Python 3.8+
- sdhash
- MySQL 数据库
- Ghidra(请提前编译好)

### 必要的Python库
```bash
pip install ssdeep pyOpenSSL pycryptodome mysql-connector-python argparse
```

### 必要的子模块clone
```bash
# 在根目录下执行如下命令，将子模块内容也clone下来（确保可以连接到github）
git submodule update --init --recursive

sudo chmod +x firmwalker_pro/firmwalker.sh
```

## 安装步骤

```bash
# 1. 拉取所需的Docker镜像

# 拉取SATC镜像
docker pull smile0304/satc:latest

# 拉取Binwalk镜像（用于固件解包）
docker pull fitzbc/binwalk 

# 2.安装sdhash

chmod +x ./install_sdhash.sh

./install_sdhash.sh

# 3.安装ghidra
tar -xzvf ghidra_11.0.1_PUBLIC.tar.gz

# 4. 配置并启动MySQL数据库

# 进入mysql配置目录

cd mysql

# 启动MySQL容器
docker compose up -d
```

### 提供的一键式安装脚本

```bash
chmod +x setup.sh

./setup.sh
```

## 使用方法

### 基本用法

```bash
python main.py -f /path/to/firmware.bin # 分析固件文件
```

### 启用SATC分析（会批量分析`binwalk_docker_result`下的`extract_result`中所有固件经过binwalk提取后的内容）

```bash
python main.py -f /path/to/firmware.bin --satc # 使用--satc参数可以调用SATC进行深度分析（如果遇到内存不足的问题需要进入satc的容器内修改内存限制）
```

### 参数说明
- `-f, --firmware_path`：指定要分析的固件文件路径（必需）
- `--satc`：启用SATC进行分析（可选）

## 输出结果

```bash
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
├── output_json/
│   ├── 固件名/                      # 每个固件的专属输出目录
│   │   └── 固件名_all_strings         # 从二进制文件中提取的所有字符串
│   │   │   └──all_strings.txt 
│   │   ├── output.json                  # 固件分析的主要结果
│   │   ├── func_signature.txt           # 函数签名列表
│   │   ├── func_name.txt                # 函数名列表
│   │   ├── imports.txt                  # 导入函数列表
│   │   ├── exports.txt                  # 导出函数列表
│   │   ├── symbol_name.txt              # 符号名列表
│   │   ├── string_name.txt              # 字符串名列表
│   │   ├── param_link.json              # 参数调用链信息
│   │   │
│   │   ├── keyword_extract_result/      # SATC关键词提取结果
│   │   │   └── detail/
│   │   │       ├── Clustering_result_v2.result  # 聚类结果
│   │   │       ├── API_detail.result            # API详情
│   │   │       ├── Prar_detail.result           # 参数详情
│   │   │       ├── sorted_clustering.json       # 排序后的聚类结果
│   │   │       ├── binname.list                 # 二进制文件名列表
│   │   │       ├── api_triplets.txt             # API三元组(API名,文本文件,二进制文件)
│   │   │       └── param_triplets.txt           # 参数三元组(参数名,文本文件,二进制文件)
│   │   │
│   │   ├── ghidra_extract_result/       # Ghidra提取结果
│   │   │   └── [各种子目录]/
│   │   │       └── *.result             # Ghidra分析结果文件
│   │   │
│   │   └── ghidra_output/               # Ghidra输出
│   │       ├── project/                 # Ghidra项目目录
│   │       └── 二进制文件名_ghidra_output.json  # Ghidra分析输出
```

## 数据库信息

固件分析结果会存储到MySQL数据库中以便后续查询和比对：
- `firmware_info`表：存储固件的基本信息
- `fuzzy_hashes`表：存储二进制文件的模糊哈希值