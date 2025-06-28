import subprocess
import os

# 路径配置
ghidra_path = "/path/to/ghidra_9.2_PUBLIC"
project_path = "/path/to/project"
input_file = "/root/firmware_analysis_tool/binwalk_docker_result/extract_result/_tenda_ac9.zip-0.extracted/squashfs-root/bin/echo"
output_file = "/path/to/output/results.txt"
script_path = "/path/to/FindStrings.py"

# 构建命令
command = [
    f"{ghidra_path}/support/analyzeHeadless",
    project_path, "tempProject",  # 临时项目目录和名称
    "-import", input_file,
    "-postScript", script_path,
    "-deleteProject",  # 分析完成后删除项目
    "-scriptPath", f"{ghidra_path}/Ghidra/Features/Python/ghidra_scripts"
]

# 运行Ghidra无头模式
result = subprocess.run(command, capture_output=True, text=True)

# 输出结果写入文件
with open(output_file, 'w') as f:
    f.write(result.stdout)

# 打印输出，确认
print(f"Extracted strings are written into {output_file}")
 