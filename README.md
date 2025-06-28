# Firmvulinker

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

两者可以独立运行，也可以串联使用：先批量提取固件特征，再在特征目录上执行相似度比较，形成漏洞传播图谱。

---

## 目录结构
```bash
.
├── README.md
├── firmware_analysis_tool
│   ├── Dockerfile                 # 构建依赖环境
│   ├── README.md                  # 子项目说明
│   ├── main.py                    # 分析入口
│   ├── config.yaml                # 全局配置
│   ├── output_json/               # 结果输出目录
│   └── ...                        # 其他脚本/资源
└── firmware_similarity_tool
    ├── README.md
    ├── main.py                    # 比对入口
    ├── modules/                   # 各维度比较模块代码
    └── ...                        # 其他文件
```

---

## 环境要求
- Linux 推荐 Ubuntu 22.04(纯CPU环境即可)
- Python 3.8 及以上
- Docker 与 docker-compose
- 额外依赖：sdhash、Ghidra、MySQL

完整依赖及安装脚本请参考各子文件夹 README。

---

## 快速开始
### 1. 克隆仓库
```bash
git clone --recursive <repo_url>
cd firmvulinker
```

### 2. 固件特征提取示例
```bash
cd firmware_analysis_tool
python main.py -f /path/to/firmware.bin            # 基础特征提取
python main.py -f /path/to/firmware.bin --satc     # 额外启用 SATC 漏洞分析
```
提取结果位于 `firmware_analysis_tool/output_json/<固件名>/`，同时核心信息写入 MySQL 数据库。

### 3. 固件相似度比较示例
```bash
cd ../firmware_similarity_tool
python main.py <固件1特征目录> <固件2特征目录>           # 默认启用全部模块
python main.py <固件1特征目录> <固件2特征目录> --modules binwalk,ghidra # 仅选择部分模块
```
单次比较结果会生成在 `comparison_results/<固件1>_<固件2>_<时间戳>/`，`comparison_summary.json` 为总览分数。

---

## 典型工作流
1. 使用 `firmware_analysis_tool` 批量对固件镜像进行解包、分析并写入数据库。
2. 调用 `firmware_similarity_tool` 读取特征目录或数据库信息，对新固件与已有固件进行多维度相似度比较。
3. 结合高相似度固件历史漏洞记录，实现漏洞迁移检测与补丁验证。

---

## 结果示例
```json
{
  "firmware1": "BM-2024-00005",
  "firmware2": "BM-2024-00003",
  "total_similarity": 0.87,
  "module_results": {
    "binwalk": 0.84,
    "filesystem_profile": 0.90,
    "interface_exposure": 0.92,
    "ghidra": 0.88,
    "param": 0.80
  }
}
```