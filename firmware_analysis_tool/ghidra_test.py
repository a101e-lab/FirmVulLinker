import subprocess
import shutil
import os
# 设置Ghidra的headless分析器路径和相关参数
ghidra_headless_path = '/home/firmware_analysis_tool/ghidra_11.0.1_PUBLIC/support/analyzeHeadless'
project_path = '/home/firmware_analysis_tool/ghidra_output/project'
if not os.path.exists(project_path):
    os.makedirs(project_path)
project_name = 'TestProject'
# input_file = '/root/firmware_analysis_tool/processed/_DAP-1665_REVB_FIRMWARE_PATCH_v2.02B01_BETA.zip.extracted/_DAP1665_FW202beta01_hboe.bin.extracted/squashfs-root/bin/busybox'

output_path = '/home/firmware_analysis_tool/ghidra_output'
script_path = '/home/firmware_analysis_tool/ghidra_script/ExtractSymbols_one.py'
strings_path = '/root/firmware_analysis_tool/ghidra_script/extract_strings.py'
# 构建命令行参数
output_file = output_path + "/bin_info_test_0108.json"
file_list = [
    "/home/firmware_analysis_tool/binwalk_docker_result/extract_result/_DAP-1665_REVB_FIRMWARE_PATCH_v2.02B01_BETA.zip.extracted/_DAP1665_FW202beta01_hboe.bin.extracted/squashfs-root/bin/busybox",
    "/home/firmware_analysis_tool/binwalk_docker_result/extract_result/_DAP-1665_REVB_FIRMWARE_PATCH_v2.02B01_BETA.zip.extracted/squashfs-root/bin/mDNSResponderPosix"
]
file_list_str = ','.join(file_list)
input_file = "/home/firmware_analysis_tool/binwalk_docker_result/extract_result/_DAP-1665_REVB_FIRMWARE_PATCH_v2.02B01_BETA.zip.extracted/_DAP1665_FW202beta01_hboe.bin.extracted/squashfs-root/bin/busybox"
args = [
    ghidra_headless_path,
    project_path,
    project_name,
    '-import', input_file,
    '-postScript', script_path, output_file,  # 如果你有自定义脚本要运行
    # '-scriptPath', '/path/to/ghidra_scripts',
    '-deleteProject',  # 如果完成后你想删除Ghidra项目
]

# 执行Ghidra headless分析命令
result =subprocess.run(args)
print(result)
# output_file='/root/firmware_analysis_tool/ghidra_output/symbols.txt'
# 输出结果写入文件
# with open(output_file, 'w') as f:
#     f.write(result.stdout)

# shutil.rmtree(project_path)
# 打印输出，确认
print(f"Extracted strings are written into {output_file}")