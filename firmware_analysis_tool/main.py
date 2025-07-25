import os
import subprocess
import json
import re
import argparse
import hashlib
import shutil  # 添加这个导入用于文件操作
import extract_file
import extract_bininfo
from config_loader import load_config
from operate_database import store_firmware_info, store_fuzzy_hashes
from mapping_ids import apply_signature_mapping

# 全局变量
HEADLESS_GHIDRA = ""

def hash_file(file_path):
    """计算文件的SHA-256哈希值"""
    if not os.path.exists(file_path):
        return None
    
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def ghidra_analysis(project_path, project_name, input_file, script_path, output_file):
    """
    使用Ghidra进行二进制分析
    """
    # 创建Ghidra项目目录
    os.makedirs(project_path, exist_ok=True)
    
    # 构建Ghidra命令
    ghidra_cmd = [
        HEADLESS_GHIDRA,
        project_path,
        project_name,
        "-import", input_file,
        "-scriptPath", os.path.dirname(script_path),
        "-postScript", os.path.basename(script_path),
        output_file
    ]
    
    # 执行Ghidra分析
    try:
        result = subprocess.run(ghidra_cmd, check=True, capture_output=True, text=True)
        print(f"Ghidra analysis completed for {input_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running Ghidra: {e}")
        if e.stdout:
            print(f"Ghidra stdout: {e.stdout}")
        if e.stderr:
            print(f"Ghidra stderr: {e.stderr}")
        return False

def extract_and_write_keys(json_files, output_path, firmware_name):
    """
    整合ghidra提取的函数名、导入、导出、符号等信息到json中

    参数:
    json_files (list): JSON 文件路径列表
    output_path (str): 输出文件夹路径
    firmware_name (str): 固件名称
    """
    keys = ["func_signature", "func_name", "imports", "exports", "symbol_name", "string_name"]
    extracted_data = {key: [] for key in keys}

    valid_files = []
    # 检查文件是否存在
    for json_file in json_files:
        if os.path.exists(json_file):
            valid_files.append(json_file)
        else:
            print(f"警告：文件 {json_file} 不存在，将跳过")
    
    for json_file in valid_files:
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                if "functions" in data:
                    for function in data["functions"]:
                        for key in ["func_signature", "func_name"]:
                            if key in function:
                                extracted_data[key].append(function[key])
                for key in ["imports", "exports", "symbols", "strings"]:
                    if key in data:
                        if key == "symbols":
                            for symbol in data[key]:
                                if "symbol_name" in symbol:
                                    extracted_data["symbol_name"].append(symbol["symbol_name"])
                        elif key == "strings":
                            for string in data[key]:
                                if "string_name" in string:
                                    extracted_data["string_name"].append(string["string_name"])
                        else:
                            extracted_data[key].extend(data[key])
        except json.JSONDecodeError:
            print(f"警告：文件 {json_file} 不是有效的JSON格式，将跳过")
        except Exception as e:
            print(f"处理文件 {json_file} 时发生错误: {e}")

    # 将结果写入固件专属目录
    firmware_output_path = os.path.join(output_path, firmware_name)
    for key in keys:
        output_file = os.path.join(firmware_output_path, f"{key}.txt")
        with open(output_file, 'w') as f:
            for item in extracted_data[key]:
                f.write(f"{item}\n")

def extract_firmware_info(firmware_path, binwalk_log_dir, firmware_extracted_folder, firmwalker_path, firmwalker_output_path, output_json_path):
    """
    提取固件信息
    """
    firmware_name_parts = os.path.basename(firmware_path).split(".")[:-1]  # 去掉文件名后缀
    if firmware_name_parts:
        firmware_name = ".".join(firmware_name_parts)
    else:
        firmware_name = os.path.basename(firmware_path)
    
    firmware_data = {
        'firmware_name': firmware_name
    }
    
    # 创建固件专属输出目录
    firmware_output_path = os.path.join(output_json_path, firmware_name)
    os.makedirs(firmware_output_path, exist_ok=True)
    
    # 创建字符串输出目录
    strings_output_path = os.path.join(firmware_output_path, f"{firmware_name}_all_strings")
    os.makedirs(strings_output_path, exist_ok=True)
    
    hash_value = update_firmware_hash(firmware_path)
    firmware_data.update({'hash_value': hash_value})
    
    # 使用binwalk提取固件
    binwalk_output_file = os.path.join(binwalk_log_dir, firmware_name + "_output.log")
    binwalk_json_file = os.path.join(binwalk_log_dir, firmware_name + ".json")
    
    # 使用Docker运行binwalk
    config = load_config()
    docker_firmware_path = "/firmware"
    docker_output_path = "/output"
    docker_binwalk_log = "/binwalk_log"
    
    binwalk_cmd = [
        'docker', 'run', 
        # '--rm',
        '-v', f'{os.path.abspath(os.path.dirname(firmware_path))}:{docker_firmware_path}',
        '-v', f'{firmware_extracted_folder}:{docker_output_path}',
        '-v', f'{binwalk_log_dir}:{docker_binwalk_log}',
        config["docker"]["binwalk_image"],
        '-Mer', f'{docker_firmware_path}/{os.path.basename(firmware_path)}',
        '-C', docker_output_path,
        '--log', f'{docker_binwalk_log}/{firmware_name}_output.log',
        '--json', f'{docker_binwalk_log}/{firmware_name}.json','--run-as=root'
    ]
    print(binwalk_cmd)
    subprocess.run(binwalk_cmd)

    # 提取架构信息
    architecture_result = extract_architecture(firmware_path)
    firmware_data.update({'architecture': architecture_result})
    
    # 提取文件系统信息
    firmware_extracted_path = os.path.join(firmware_extracted_folder, "_" + os.path.basename(firmware_path) + ".extracted")
    filesystem_path = find_squashfs_root(firmware_extracted_path)
    
    if filesystem_path:
        filesystem_result = "squashfs"
    else:
        filesystem_result = None
    
    firmware_data.update({'filesystem': filesystem_result})
    
    # 提取操作系统信息
    operating_system_result = None
    if filesystem_path:
        # 检查是否存在/etc/os-release文件
        os_release_path = os.path.join(filesystem_path, "etc/os-release")
        if os.path.exists(os_release_path):
            with open(os_release_path, 'r') as f:
                os_release_content = f.read()
                if "ID=" in os_release_content:
                    operating_system_result = os_release_content.split("ID=")[1].split("\n")[0].strip('"')
        
        # 如果没有找到os-release，尝试其他方法
        if not operating_system_result:
            # 检查是否存在/bin/busybox
            if os.path.exists(os.path.join(filesystem_path, "bin/busybox")):
                operating_system_result = "BusyBox"
            # 检查是否存在/proc目录
            elif os.path.exists(os.path.join(filesystem_path, "proc")):
                operating_system_result = "Linux"
    
    firmware_data.update({'operating_system': operating_system_result})
    
    # 提取文件信息
    if not filesystem_path and not os.path.exists(firmware_extracted_path):
        pass
    elif not filesystem_path:
        pass
    else:  # 成功提取文件系统后才能进一步提取信息
        search_files, file_set, ip_addresses, urls, emails = extract_file_info(firmware_extracted_path, firmwalker_path, firmwalker_output_path, filesystem_path)
        firmware_data.update({"file_info": search_files})
        firmware_data.update({"file_set": list(file_set)})
        firmware_data.update({"ip_addresses": ip_addresses})
        firmware_data.update({"urls": urls})
        firmware_data.update({"emails": emails})
        key_dic = {}
        ca_list = []
        
        for value in firmware_data["file_info"]["SSL related files"].values():
            if value:
                for v in value.split("\n"):
                    ca_list = extract_file.extract_ca_file(v, ca_list)
                    
                    private_key_dic = {}
                    public_key_dic = {}
                    public_private_keyfile_hash = {}
                    key_list = []
                    key_file_path = os.path.join(filesystem_path, v)
                    key_file_hash = hash_file(key_file_path)
                    public_private_keyfile_hash["file_hash"] = key_file_hash
                    key_list.append(public_private_keyfile_hash)
                    private_key_output, public_key_output = extract_file.extract_public_private_key(key_file_path)
                    if private_key_output or public_key_output:
                        private_key_dic["private_key"] = private_key_output
                        public_key_dic["public_key"] = public_key_output
                        
                        key_list.append(private_key_dic)
                        key_list.append(public_key_dic)
                        key_dic[v] = key_list
                    else:
                        key_dic[v] = key_list
            else:
                continue
                
        firmware_data.update({"public_private_key": key_dic})
        ca_file_hashes = {}
        for ca_file in ca_list:
            ca_file_path = os.path.join(filesystem_path, ca_file)
            if os.path.exists(ca_file_path):
                ca_file_hash = hash_file(ca_file_path)
            ca_file_hashes[ca_file] = ca_file_hash
        firmware_data.update({"ca_file_hashes": ca_file_hashes})

        bin_list, bin_path_list = extract_file.extract_bin_file(firmware_extracted_path, filesystem_path)
        bin_file_info = [os.path.basename(bin_path) for bin_path in bin_path_list]
        firmware_data.update({"bin_file_info": bin_file_info})
        
        # 存储 firmware_info 信息
        firmware_id = store_firmware_info(hash_value, firmware_name, architecture_result, filesystem_result, operating_system_result)
        store_fuzzy_hashes(firmware_id, bin_list)
        
        configuration_list = extract_file.extract_configuration_file(firmware_extracted_path)
        firmware_data.update({"configuration_file_info": configuration_list})

        directory_structure = extract_file.extract_directory(filesystem_path)
        firmware_data.update({"directory_structure_info": list(directory_structure)})
        
        # 提取二进制信息
        all_strings = set()
        for file in bin_path_list:
            extracted_strings = extract_bininfo.extract_strings(file, filesystem_path, strings_output_path)
            all_strings.update(extracted_strings)

        with open(os.path.join(strings_output_path, "all_strings.txt"), "w") as f:
            for string in sorted(all_strings):
                f.write(string + "\n")
    
    # 将结果写入固件专属目录
    with open(os.path.join(firmware_output_path, "output.json"), "w") as json_file:
        json.dump(firmware_data, json_file, indent=4)
            
    return firmware_data, filesystem_path

def update_firmware_hash(firmware_path):
    """
    计算固件哈希值
    """
    with open(firmware_path, 'rb') as file:
        firmware_content = file.read()
    hash_value = hashlib.sha256(firmware_content).hexdigest()
    return hash_value

def extract_architecture(firmware_path):
    """
    用binwalk从固件中提取架构信息
    """
    # binwalk -A提取架构信息
    architecture_cmd = ["binwalk", "-A", firmware_path, "--run-as=root"]
    result = subprocess.run(architecture_cmd, capture_output=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout
    index = output.find('instructions')
    if index != -1:
        start_index = output.rfind(' ', 0, index-1) + 1
        end_index = output.rfind(' ', 0, index)
        architecture = output[start_index:end_index]
        return architecture
    else:
        return None

def extract_file_info(firmware_extracted_path, firmwalker_path, firmwalker_output_path, filesystem_path):
    """
    运行firmwalker脚本，提取敏感文件信息
    """
    firmware_name_parts = os.path.basename(firmware_extracted_path).split(".")[:-2]
    firmware_name_parts_2 = ".".join(firmware_name_parts).split("_")[1:]
    firmware_name = "_".join(firmware_name_parts_2)
    
    # 执行firmwalker脚本
    os.chdir(firmwalker_path)
    firmwalker_output_file = os.path.join(firmwalker_output_path, firmware_name + "_firmwalker.txt")
    if os.path.exists(firmwalker_output_file):
        search_files, file_set, ip_addresses, urls, emails = process_firmwalker_result(firmwalker_output_file)
    else:    
        binwalk_cmd = ["./firmwalker.sh", filesystem_path, firmwalker_output_file]
        subprocess.run(binwalk_cmd)
        search_files, file_set, ip_addresses, urls, emails = process_firmwalker_result(firmwalker_output_file)
    return search_files, file_set, ip_addresses, urls, emails

def process_firmwalker_result(firmwalker_output_path):
    """
    处理firmwalker结果
    """
    with open(firmwalker_output_path, 'r') as file:
        firmwalker_content = file.read()
        lines = firmwalker_content.splitlines()
        paragraphs_dic = {}
        detailed_paragraphs_dic = {}
        patterns_paragraphs_dic = {}

        ip_addresses = []
        urls = []
        emails = []
        
        current_paragraph = ""
        start_new_paragraph = False
        search_for_flag = ""
        
        for line in lines:
            if line.startswith("***"):
                if current_paragraph:
                    paragraphs_dic[search_for_flag] = current_paragraph.strip()
                current_paragraph = ""
                start_new_paragraph = True
                search_for_flag = line.replace("***", "").replace("Search for", "").strip()
            else:
                if line.strip() != "":
                    start_new_paragraph = False
                    # 删除路径中的"-root/"前缀
                    if "-root/" in line:
                        line = line.replace("-root/", "")
                    # 删除路径中的"t/"前缀
                    if line.startswith("t/"):
                        line = line[2:]  # 删除前两个字符 "t/"
                    current_paragraph += line + "\n"
        if current_paragraph:
            paragraphs_dic[search_for_flag] = current_paragraph.strip()
    
    start_index = 1
    for index, (key, value) in enumerate(paragraphs_dic.items()):
        parts_paragraphs_dic = {}
        if index < start_index:
            continue 
        else:     
            current_paragraph = ""
            start_new_paragraph = False
            file_flag = key
            patterns_flag = ""
            patterns_paragraph = ""
            start_new_patterns_paragraph = True
            if key == "patterns in files":
                for pattern in paragraphs_dic[key].split("\n"):
                    if pattern.startswith("--------------------") and pattern.replace("--------------------", "").strip() != "":
                        if start_new_patterns_paragraph:
                            patterns_flag = pattern.replace("--------------------", "").strip()
                            patterns_paragraphs_dic[patterns_flag] = patterns_paragraph.strip()
                        else:
                            patterns_paragraphs_dic[patterns_flag] = patterns_paragraph.strip()
                            patterns_flag = pattern.replace("--------------------", "").strip()
                            patterns_paragraph = ""
                            patterns_paragraphs_dic[patterns_flag] = patterns_paragraph.strip()
                        patterns_paragraph = ""
                        start_new_patterns_paragraph = True
                    else:
                        if pattern.replace("--------------------", "").strip() != "":
                            start_new_patterns_paragraph = False
                            patterns_paragraph += pattern + "\n"
                patterns_paragraphs_dic[patterns_flag] = patterns_paragraph.strip()        
            # 将IP地址、URL和电子邮件添加到列表中
            elif key == "ip addresses":
                for v in paragraphs_dic[key].split("\n"):
                    if v.strip() and not v.startswith("#####################################"):
                        ip_addresses.append(v.strip())
            elif key == "urls":
                for v in paragraphs_dic[key].split("\n"):
                    if v.strip() and not v.startswith("#####################################"):
                        urls.append(v.strip())
            elif key == "emails":
                for v in paragraphs_dic[key].split("\n"):
                    if v.strip() and not v.startswith("#####################################"):
                        emails.append(v.strip())
            else:    
                for v in paragraphs_dic[key].split("\n"):
                    if v.startswith("#####################################") and v.replace("#####################################", "").strip() != "":
                        file_flag = v.replace("#####################################", "").strip()
                        parts_paragraphs_dic[file_flag] = current_paragraph.strip()
                        current_paragraph = "" 
                        start_new_paragraph = True
                    else:
                        if v.replace("#####################################", "").strip() != "":
                            start_new_paragraph = False
                            current_paragraph += v + "\n"
                parts_paragraphs_dic[file_flag] = current_paragraph.strip()
        detailed_paragraphs_dic[key] = parts_paragraphs_dic
    detailed_paragraphs_dic["patterns in files"] = patterns_paragraphs_dic
    
    # 移除IP、URL和电子邮件信息键
    keys_to_remove = ["ip addresses", "urls", "emails"]
    for key in keys_to_remove:
        if key in detailed_paragraphs_dic:
            del detailed_paragraphs_dic[key]
    
    # 输出文件集合
    file_set = set()
    for key, value in detailed_paragraphs_dic.items():
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if sub_value:
                    files = sub_value.split('\n')
                    for file in files:
                        file_name = os.path.basename(file.strip())
                        file_set.add(file_name)
        else:
            if value:
                files = value.split('\n')
                for file in files:
                    file_name = os.path.basename(file.strip())
                    file_set.add(file_name)

    # 返回详细信息字典、文件集合，以及IP、URL和电子邮件列表
    return detailed_paragraphs_dic, file_set, ip_addresses, urls, emails

def find_squashfs_root(firmware_extracted_path):
    """
    找到文件系统的路径，还需添加其他文件系统的名字
    """
    for root, directories, files in os.walk(firmware_extracted_path):
        if os.path.basename(root) == "squashfs-root":
            if os.path.exists(os.path.abspath(root)):
                return os.path.abspath(root)
            else:
                return None
    return None

def run_satc(firmware_extracted_folder, output_json_path, firmware_name):
    """
    运行SATC工具进行分析
    """
    try:
        # 创建固件专属目录下的子目录
        firmware_output_path = os.path.join(output_json_path, firmware_name)
        os.makedirs(firmware_output_path, exist_ok=True)
        
        keyword_extract_result = os.path.join(firmware_output_path, "keyword_extract_result")
        os.makedirs(keyword_extract_result, exist_ok=True)
        
        keyword_detail_dir = os.path.join(keyword_extract_result, "detail")
        os.makedirs(keyword_detail_dir, exist_ok=True)
        
        ghidra_extract_result = os.path.join(firmware_output_path, "ghidra_extract_result")
        os.makedirs(ghidra_extract_result, exist_ok=True)
        
        # 使用Docker运行SATC
        config = load_config()
        docker_cmd = [
            'docker', 'run',
            '-v', f'{firmware_extracted_folder}:/home/satc/SaTC/firmware_extracted',
            '-v', f'{output_json_path}:/home/satc/SaTC/output',
            '--entrypoint', '/bin/sh',
            '--privileged=true',
            config["docker"]["satc_image"],
            '-c', 'chmod -R 777 /home/satc/SaTC/firmware_extracted && chmod -R 777 /home/satc/SaTC/output && su satc -c "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && workon SaTC && cd /home/satc/SaTC/ && python satc.py -d /home/satc/SaTC/firmware_extracted -o /home/satc/SaTC/output --ghidra_script=ref2sink_cmdi --ghidra_script=ref2sink_bof"'
        ]
        
        
        subprocess.run(docker_cmd, check=True)
        
        # 移动SATC输出到固件专属目录
        src_ghidra_extract = os.path.join(output_json_path, "ghidra_extract_result")
        src_keyword_extract = os.path.join(output_json_path, "keyword_extract_result")
        
        # 如果源目录存在，移动其内容到目标目录
        if os.path.exists(src_ghidra_extract):
            for item in os.listdir(src_ghidra_extract):
                src_item = os.path.join(src_ghidra_extract, item)
                dst_item = os.path.join(ghidra_extract_result, item)
                if os.path.isdir(src_item):
                    shutil.copytree(src_item, dst_item, dirs_exist_ok=True)
                else:
                    shutil.copy2(src_item, dst_item)
            shutil.rmtree(src_ghidra_extract)
            
        if os.path.exists(src_keyword_extract):
            for item in os.listdir(src_keyword_extract):
                src_item = os.path.join(src_keyword_extract, item)
                if item == "detail":
                    for detail_item in os.listdir(src_item):
                        src_detail_item = os.path.join(src_item, detail_item)
                        dst_detail_item = os.path.join(keyword_detail_dir, detail_item)
                        shutil.copy2(src_detail_item, dst_detail_item)
                else:
                    dst_item = os.path.join(keyword_extract_result, item)
                    if os.path.isdir(src_item):
                        shutil.copytree(src_item, dst_item, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src_item, dst_item)
            shutil.rmtree(src_keyword_extract)
            
    except subprocess.CalledProcessError as e:
        print(f"Error running SATC: {e}")
        print(f"Command output: {e.output}")

def sort_borderbin(clustering_result_path, filesystem_path, firmware_name):
    """
    对BorderBin的聚类结果进行排序
    """
    results = []
    with open(clustering_result_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
        # 使用正则表达式匹配程序名和计数
        program_matches = re.finditer(
            r'Program name : (.*?)\nStrings count : (\d+)\nPara \+ API count : (\d+).*?Hits Para count: (\d+).*?Number of Para source files: (\d+).*?Hits API count: (\d+).*?Number of API source files: (\d+)', 
            content, re.DOTALL
        )
        
        # 收集所有匹配结果
        for match in program_matches:
            program_name = match.group(1).strip()
            strings_count = int(match.group(2).strip())
            para_api_count = int(match.group(3).strip())
            para_count = int(match.group(4).strip())
            para_source_files = int(match.group(5).strip())
            api_count = int(match.group(6).strip())
            api_source_files = int(match.group(7).strip())
            vector = [strings_count, para_api_count, para_count, para_source_files, api_count, api_source_files]
            results.append({
                "program_name": program_name,
                "strings_count": strings_count,
                "para_api_count": para_api_count,
                "para_count": para_count,
                "numof_para_source_files": para_source_files,
                "api_count": api_count,
                "numof_api_source_files": api_source_files,
                os.path.basename(program_name): vector
            })
        
        # 按 Para + API count 降序排序
        results.sort(key=lambda x: x["para_api_count"], reverse=True)
    
    # 修改输出文件路径到固件专属目录下的detail子目录
    detail_dir = os.path.join(os.path.dirname(clustering_result_path))
    output_path = os.path.join(detail_dir, 'sorted_clustering.json')
    
    # 写入结果到json文件
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)
    print("sorted_clustering.json finished")
    print("sorted_clustering.json path: ", output_path)
    
    # 提取 program_name 中的文件名并写入 binname.list 文件
    binname_list_path = os.path.join(detail_dir, 'binname.list')
    with open(binname_list_path, 'w', encoding='utf-8') as f:
        for result in results:
            bin_name = os.path.basename(result["program_name"])
            f.write(f"{bin_name}\n")
    print("binname.list finished")
    print("binname.list path: ", binname_list_path)
    
    # 输出排序的前3个程序的相对路径
    top_3_programs = [re.sub(r".*/squashfs-root", filesystem_path, program["program_name"]) for program in results[:3]]
    return top_3_programs

def extract_api_triplets(api_detail_path, firmware_name):
    """
    提取 API 的 name、所属的 text file 和所属的 bin file，形成三元组，输出到 api_triplets.txt 中。
    """
    triplets = []

    with open(api_detail_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
        # 使用正则表达式匹配 API name、Text File 和 Bin File
        api_matches = re.finditer(
            r'API name : (.*?)\nSource File : \n\tText File: \n\t\t(.*?)\n\tBin File: \n\t\t(.*?)\n',
            content, re.DOTALL
        )
        
        for match in api_matches:
            api_name = match.group(1).strip()
            text_file = os.path.basename(match.group(2).strip())
            bin_file = os.path.basename(match.group(3).strip())
            triplets.append((api_name, text_file, bin_file))
    
    # 修改输出文件路径到固件专属目录下的detail子目录
    detail_dir = os.path.dirname(api_detail_path)
    output_path = os.path.join(detail_dir, 'api_triplets.txt')
    
    # 写入结果到 api_triplets.txt 文件
    with open(output_path, 'w', encoding='utf-8') as f:
        for triplet in triplets:
            f.write(f"{triplet[0]}, {triplet[1]}, {triplet[2]}\n")

def extract_param_triplets(param_detail_path, firmware_name):
    """
    提取参数的 name、所属的 text file 和所属的 bin file，形成三元组，输出到 param_triplets.txt 中。
    """
    triplets = []

    with open(param_detail_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
        # 使用正则表达式匹配 Prar name、Text File 和 Bin File
        param_matches = re.finditer(
            r'Prar name : (.*?)\nSource File : \n\tText File: \n\t\t(.*?)\n\tBin File: \n\t\t(.*?)\n',
            content, re.DOTALL
        )
        
        for match in param_matches:
            param_name = match.group(1).strip()
            text_file = os.path.basename(match.group(2).strip())
            bin_file = os.path.basename(match.group(3).strip())
            triplets.append((param_name, text_file, bin_file))
    
    # 修改输出文件路径到固件专属目录下的detail子目录
    detail_dir = os.path.dirname(param_detail_path)
    output_path = os.path.join(detail_dir, 'param_triplets.txt')
    
    # 写入结果到 param_triplets.txt 文件
    with open(output_path, 'w', encoding='utf-8') as f:
        for triplet in triplets:
            f.write(f"{triplet[0]}, {triplet[1]}, {triplet[2]}\n")

def extract_params_from_result_files(directory, output_path, firmware_name):
    """
    整合参数调用链

    参数:
    directory (str): 要遍历的目录路径
    output_path (str): 输出路径
    firmware_name (str): 固件名称
    """
    result_data = {}

    # 遍历目录及其子目录
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".result"):
                subdir_name = os.path.basename(root)
                result_file_path = os.path.join(root, file)
                
                # 初始化子目录名为键的列表
                if subdir_name not in result_data:
                    result_data[subdir_name] = []

                # 读取文件并提取以 [Param 开头的行
                with open(result_file_path, 'r') as f:
                    for line in f:
                        if line.startswith("[Param"):
                            result_data[subdir_name].append(line.strip())
    
    # 修改输出路径到固件专属目录
    firmware_output_path = os.path.join(output_path, firmware_name)
    param_link_path = os.path.join(firmware_output_path, "param_link.json")
    with open(param_link_path, 'w', encoding='utf-8') as f:
        json.dump(result_data, f, indent=4, ensure_ascii=False)

def update_firmware_hash(firmware_path):
    """计算固件文件的哈希值"""
    return hash_file(firmware_path)

def extract_architecture(firmware_path):
    """提取固件的架构信息"""
    try:
        result = subprocess.run(['file', firmware_path], capture_output=True, text=True)
        output = result.stdout.lower()
        
        if 'mips' in output:
            return 'MIPS'
        elif 'arm' in output:
            return 'ARM'
        elif 'x86' in output:
            return 'x86'
        elif 'powerpc' in output:
            return 'PowerPC'
        else:
            return 'Unknown'
    except Exception as e:
        print(f"Error extracting architecture: {e}")
        return 'Unknown'

def find_squashfs_root(firmware_extracted_path):
    """
    找到文件系统的路径，还需添加其他文件系统的名字
    """
    for root, directories, files in os.walk(firmware_extracted_path):
        if os.path.basename(root) == "squashfs-root":
            if os.path.exists(os.path.abspath(root)):
                return os.path.abspath(root)
            else:
                return None
    return None

def process_firmwalker_output(firmwalker_output_file, firmware_data):
    """处理firmwalker输出文件，提取敏感信息"""
    sensitive_info = {}
    
    if os.path.exists(firmwalker_output_file):
        with open(firmwalker_output_file, 'r') as f:
            content = f.read()
            
            # 提取敏感文件信息
            sections = content.split("\n\n")
            for section in sections:
                if section.strip():
                    lines = section.strip().split("\n")
                    if len(lines) > 0:
                        section_title = lines[0].strip("[]")
                        section_items = [line.strip() for line in lines[1:] if line.strip()]
                        if section_items:
                            sensitive_info[section_title] = section_items
    
    firmware_data.update({"sensitive_info": sensitive_info})
    return firmware_data

def parse_firmwalker_output(firmwalker_output_file, firmware_data):
    """解析firmwalker输出，提取详细段落"""
    detailed_paragraphs_dic = {}
    file_set = set()
    
    if os.path.exists(firmwalker_output_file):
        with open(firmwalker_output_file, 'r') as f:
            content = f.read()
            
            # 按空行分割内容为段落
            paragraphs = content.split("\n\n")
            paragraphs_dic = {}
            
            for paragraph in paragraphs:
                if paragraph.strip():
                    lines = paragraph.strip().split("\n")
                    if len(lines) > 0:
                        key = lines[0].strip("[]")
                        value = "\n".join(lines[1:])
                        paragraphs_dic[key] = value
            
            # 处理段落
            for key in paragraphs_dic:
                parts_paragraphs_dic = {}
                patterns_paragraphs_dic = {}
                current_paragraph = ""
                start_new_paragraph = True
                file_flag = ""
                
                if key == "Search for patterns in files":
                    patterns_paragraph = ""
                    patterns_flag = ""
                    
                    for pattern in paragraphs_dic[key].split("\n"):
                        if pattern.startswith("--------------------") and pattern.replace("--------------------", "").strip() != "":
                            if patterns_paragraph.strip():
                                patterns_paragraphs_dic[patterns_flag] = patterns_paragraph.strip()
                            patterns_flag = pattern.replace("--------------------", "").strip()
                            patterns_paragraph = ""
                        else:
                            patterns_paragraph += pattern + "\n"
                    patterns_paragraphs_dic[patterns_flag] = patterns_paragraph.strip()        
                else:    
                    for v in paragraphs_dic[key].split("\n"):
                        if v.startswith("#####################################") and v.replace("#####################################", "").strip() != "":
                            file_flag = v.replace("#####################################", "").strip()
                            parts_paragraphs_dic[file_flag] = current_paragraph.strip()
                            current_paragraph = "" 
                            start_new_paragraph = True
                        else:
                            if v.replace("#####################################", "").strip() != "":
                                start_new_paragraph = False
                                current_paragraph += v + "\n"
                    parts_paragraphs_dic[file_flag] = current_paragraph.strip()
                detailed_paragraphs_dic[key] = parts_paragraphs_dic
            detailed_paragraphs_dic["patterns in files"] = patterns_paragraphs_dic
            
            # 输出文件集合        
            for key, value in detailed_paragraphs_dic.items():
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        if sub_value:
                            files = sub_value.split('\n')
                            for file in files:
                                file_name = os.path.basename(file.strip())
                                file_set.add(file_name)
                else:
                    if value:
                        files = value.split('\n')
                        for file in files:
                            file_name = os.path.basename(file.strip())
                            file_set.add(file_name)

    return detailed_paragraphs_dic, file_set

def main():
    # 加载配置
    config = load_config()
    
    # 设置 Ghidra 路径
    global HEADLESS_GHIDRA
    HEADLESS_GHIDRA = config["tool"]["ghidra"]["headless_full_path"]
    
    # 设置各种目录
    binwalk_log_dir = config["directories"]["binwalk_log"]
    if not os.path.exists(binwalk_log_dir):
        os.makedirs(binwalk_log_dir)
        
    output_json_path = config["directories"]["output_json"]
    if not os.path.exists(output_json_path):
        os.makedirs(output_json_path)
        
    firmware_extracted_folder = config["directories"]["firmware_extracted"]
    if not os.path.exists(firmware_extracted_folder):
        os.makedirs(firmware_extracted_folder)
        
    firmwalker_path = config["directories"]["firmwalker"]
    firmwalker_output_path = config["directories"]["firmwalker_output"]
    if not os.path.exists(firmwalker_output_path):
        os.makedirs(firmwalker_output_path)
    
    # 命令行参数解析
    parser = argparse.ArgumentParser(description="Firmware Analysis Tool")
    parser.add_argument('-f', '--firmware_path', type=str, required=True, help="Firmware path for analysis")
    parser.add_argument('--satc', action='store_true', help="Enable SATC analysis")
    parser.add_argument('--config', type=str, default="config.yaml", help="Path to config file")
    
    args = parser.parse_args()
    
    # 如果指定了不同的配置文件，重新加载
    if args.config != "config.yaml":
        config = load_config(args.config)
    
    if args.firmware_path:
        firmware_path = args.firmware_path
        firmware_info_result, filesystem_path = extract_firmware_info(
            firmware_path,
            binwalk_log_dir,
            firmware_extracted_folder,
            firmwalker_path,
            firmwalker_output_path,
            output_json_path
        )
        
        # 获取固件名称
        firmware_name = firmware_info_result['firmware_name']

    # 应用签名映射到binwalk日志文件
    mapping_file_name = config.get("mapping", {}).get("signature_mapping_file", "signatures_medium_grained.json")
    mapping_file_path = os.path.join(os.path.dirname(__file__), mapping_file_name)
    if os.path.exists(mapping_file_path):
        print(f"\n开始对固件 {firmware_name} 的binwalk结果应用签名映射...")
        processed_count, updated_count = apply_signature_mapping(binwalk_log_dir, mapping_file_path, firmware_name)
    else:
        print(f"警告: 映射文件 {mapping_file_path} 不存在，跳过签名映射步骤")

    if args.satc:
        # 运行SATC并将输出放在固件专属目录下
        run_satc(firmware_extracted_folder, output_json_path, firmware_name)
        
        # 创建固件专属目录下的子目录
        firmware_output_path = os.path.join(output_json_path, firmware_name)
        keyword_extract_result = os.path.join(firmware_output_path, "keyword_extract_result")
        detail_dir = os.path.join(keyword_extract_result, "detail")
        
        # SATC 相关路径配置
        clustering_result_path = os.path.join(detail_dir, "Clustering_result_v2.result")
        api_detail_path = os.path.join(detail_dir, "API_detail.result")
        param_detail_path = os.path.join(detail_dir, "Prar_detail.result")
        
        # 初始化 top_3_programs 变量，防止未定义错误
        top_3_programs = []
        
        if os.path.exists(clustering_result_path):
            top_3_programs = sort_borderbin(clustering_result_path, filesystem_path, firmware_name)
        if os.path.exists(api_detail_path):
            extract_api_triplets(api_detail_path, firmware_name)
        if os.path.exists(param_detail_path):
            extract_param_triplets(param_detail_path, firmware_name)
        
        # 只有当 top_3_programs 不为空时才执行 Ghidra 分析
        if top_3_programs:
            # Ghidra 分析
            script_path = config["tool"]["ghidra"]["script_path"]
            ghidra_output_path = os.path.join(firmware_output_path, "ghidra_output")
            os.makedirs(ghidra_output_path, exist_ok=True)
                
            json_files = []
            for input_file in top_3_programs:
                project_path = os.path.join(ghidra_output_path, "project")
                if not os.path.exists(project_path):
                    os.makedirs(project_path)
                    
                project_name = 'TestProject'
                output_file = os.path.join(ghidra_output_path, os.path.basename(input_file) + "_ghidra_output.json")

                ghidra_analysis(project_path, project_name, input_file, script_path, output_file)
                print(output_file)
                json_files.append(output_file)
                
            # 只有当json_files非空时才执行extract_and_write_keys
            if json_files:
                extract_and_write_keys(json_files, output_json_path, firmware_name)
            else:
                print(f"警告：没有生成任何Ghidra分析JSON文件")
            
            ghidra_extract_result = os.path.join(firmware_output_path, "ghidra_extract_result")
            extract_params_from_result_files(ghidra_extract_result, output_json_path, firmware_name)

if __name__ == "__main__":
    main()