# def extract_bootloader_offset_address(output_file):
#     """
#     从binwalk结果中提取引导加载程序的偏移地址
#     """
#     with open(output_file, 'r') as file:
#         content = file.read()
#         index = content.find('boot')
#         if index != -1:
#             start_index = content.rfind(' ', 0, index-1)+1
#             end_index = content.rfind(' ', 0, index)
#             filesystem = content[start_index:end_index]
#             return filesystem
#             # firmware_data.update({"filesystem": filesystem}) 
#         else:
#             return None

import subprocess
import os
import re

PARA_FILTER_STRINGS = [" ", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "+", "[", "]", ":", ";", "'", "\"", ",",  "?", "/", "<", ">", "\\", "|", "，", "？", "！", "=", "`", "~", "_"]
def is_meaningful_string(s):
    """
    判断字符串是否有意义
    """
    # 去除字符串两端的空白字符
    s = s.strip()

    # 判断其他字符
    # if s.startswith("_"):
    if len(s) > 4 and (s.isalpha() or s.isalnum()):
        return True

    # if len(s) <= 4:
    #     return False
    
    # if len(s) >= 25:
    # 判断字符串中无意义字符的数量
    count = sum(1 for filter_str in PARA_FILTER_STRINGS if filter_str in s)
    if count > 10:
        return False
    elif len(s) <= 8 and count > 2:
        return False
    # 判断字符串是否包含大量重复字符
    if len(set(s)) <= 2:
        return False
    return True
def extract_strings(binary_file, filesystem_path, firmware_strings_path, min_length=5):
    file_relpath = os.path.relpath(binary_file, filesystem_path).replace("/", "_")
    output_file = os.path.join(firmware_strings_path, file_relpath + "_strings.txt")
    extracted_strings = set()

    with open(output_file, "w") as f:
        result = subprocess.run(["strings", "-n", str(min_length), binary_file], capture_output=True, text=True)
        strings = result.stdout.splitlines()
        unique_strings = set(strings)
        for s in unique_strings:
            s = s.strip().replace(" ", "").lower()
            if is_meaningful_string(s):
                f.write(s + "\n")
                extracted_strings.add(s)
    
    return extracted_strings