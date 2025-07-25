import json
import os
import glob

def load_signature_mapping(mapping_file_path):
    """
    从指定的JSON文件加载签名ID映射。
    映射表中的 "id" 对应原始 signature_id，"medium_grained_id" 对应新的ID。
    """
    try:
        with open(mapping_file_path, 'r', encoding='utf-8') as f:
            mappings_list = json.load(f)
        
        signature_map = {}
        for item in mappings_list:
            if "id" in item and "medium_grained_id" in item:
                signature_map[item["id"]] = item["medium_grained_id"]
            else:
                print(f"警告: 映射文件 '{mapping_file_path}' 中的条目缺少 'id' 或 'medium_grained_id': {item}")
        return signature_map
    except FileNotFoundError:
        print(f"错误: 映射文件 '{mapping_file_path}' 未找到。")
        return None
    except json.JSONDecodeError:
        print(f"错误: 解析映射文件 '{mapping_file_path}' 失败。请检查JSON格式。")
        return None
    except Exception as e:
        print(f"加载映射文件时发生未知错误: {e}")
        return None

def update_json_file(file_path, signature_map):
    """
    更新单个JSON文件中的 signature_id。
    确保只进行一次映射，避免多次迭代。
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"错误: 文件 '{file_path}' 未找到。")
        return False
    except json.JSONDecodeError:
        print(f"错误: 解析JSON文件 '{file_path}' 失败。跳过此文件。")
        return False
    except Exception as e:
        print(f"读取文件 '{file_path}' 时发生未知错误: {e}")
        return False

    modified = False
    for top_key, top_value in data.items():
        if top_key == "VECTOR":
            if isinstance(top_value, list):
                new_vector_list = []
                for id_list in top_value:
                    if isinstance(id_list, list):
                        new_id_list = []
                        for sig_id in id_list:
                            # 只进行一次映射，如果原始ID在映射表中，则替换
                            new_sig_id = signature_map.get(sig_id, sig_id)
                            if new_sig_id != sig_id:
                                modified = True
                                print(f"映射: {sig_id} -> {new_sig_id}")
                            new_id_list.append(new_sig_id)
                        new_vector_list.append(new_id_list)
                    else:
                        new_vector_list.append(id_list) # 保持原样（如果内部不是列表）
                if modified: # 仅当VECTOR实际被修改时才更新
                    data[top_key] = new_vector_list
            else:
                print(f"警告: 文件 '{file_path}' 中的 'VECTOR' 字段不是列表类型。")

        elif isinstance(top_value, dict): # 处理如 "1", "2" 等主条目
            for section_key, section_value in top_value.items():
                if isinstance(section_value, dict) and "signature_id" in section_value:
                    old_sig_id = section_value["signature_id"]
                    new_sig_id = signature_map.get(old_sig_id, old_sig_id)
                    if new_sig_id != old_sig_id:
                        section_value["signature_id"] = new_sig_id
                        modified = True
    
    if modified:
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            print(f"已更新文件: {file_path}")
            return True
        except Exception as e:
            print(f"错误: 写入文件 '{file_path}' 失败: {e}")
            return False
    else:
        print(f"文件无需更新: {file_path}")
        return False

def apply_signature_mapping(binwalk_log_dir, mapping_file_path, firmware_name=None):
    """
    对指定目录下的JSON文件应用签名映射。
    
    参数:
    binwalk_log_dir (str): binwalk日志目录路径
    mapping_file_path (str): 映射文件路径
    firmware_name (str): 固件名称，如果指定则只处理该固件的JSON文件
    
    返回:
    tuple: (处理的文件数, 更新的文件数)
    """
    print(f"开始应用签名映射...")
    print(f"映射文件: {os.path.abspath(mapping_file_path)}")
    print(f"目标目录: {os.path.abspath(binwalk_log_dir)}")

    signature_map = load_signature_mapping(mapping_file_path)
    if signature_map is None:
        print("无法加载签名映射，操作终止。")
        return 0, 0

    if not signature_map:
        print("签名映射为空，没有可用的替换规则。操作终止。")
        return 0, 0
        
    # 查找JSON文件
    if firmware_name:
        # 如果指定了固件名称，只处理该固件的JSON文件
        json_file_path = os.path.join(binwalk_log_dir, f"{firmware_name}.json")
        if os.path.exists(json_file_path):
            json_files = [json_file_path]
        else:
            print(f"未找到固件 {firmware_name} 的JSON文件: {json_file_path}")
            return 0, 0
    else:
        # 处理目录下的所有JSON文件
        json_files_pattern = os.path.join(binwalk_log_dir, '*.json')
        json_files = glob.glob(json_files_pattern)
    
    if not json_files:
        print(f"在 '{binwalk_log_dir}' 下未找到JSON文件。")
        return 0, 0

    processed_files_count = 0
    updated_files_count = 0

    for json_file_path in json_files:
        processed_files_count += 1
        if update_json_file(json_file_path, signature_map):
            updated_files_count += 1
    
    return processed_files_count, updated_files_count

def main():
    workspace_root = os.getcwd() # 假设脚本从工作区根目录运行
    
    # 映射文件的路径（相对于工作区根目录）
    mapping_file_path = os.path.join('signatures_medium_grained.json')
    
    # 包含BM-*文件夹的根目录
    data_root_dir = os.path.join('test_data_all_medium')

    print(f"工作区根目录: {workspace_root}")
    print(f"使用的映射文件: {os.path.abspath(mapping_file_path)}")
    print(f"扫描的目标数据目录: {os.path.abspath(data_root_dir)}")

    signature_map = load_signature_mapping(mapping_file_path)
    if signature_map is None:
        print("无法加载签名映射，脚本终止。")
        return

    if not signature_map:
        print("签名映射为空，没有可用的替换规则。脚本终止。")
        return
        

    # 查找所有BM-*文件夹
    bm_folders_pattern = os.path.join(data_root_dir, 'BM-*')
    bm_folders = glob.glob(bm_folders_pattern)

    if not bm_folders:
        print(f"在 '{data_root_dir}' 下未找到 'BM-*' 格式的文件夹。")
        return

    processed_files_count = 0
    updated_files_count = 0

    for bm_folder in bm_folders:
        if not os.path.isdir(bm_folder):
            continue
        
        binwalk_log_dir = os.path.join(bm_folder, 'binwalk_docker_result', 'binwalk_log')
        
        if not os.path.isdir(binwalk_log_dir):
            continue
            
        # 查找该目录下的所有.json文件
        json_files_pattern = os.path.join(binwalk_log_dir, '*.json')
        json_files = glob.glob(json_files_pattern)
        
        for json_file_path in json_files:
            processed_files_count += 1
            if update_json_file(json_file_path, signature_map):
                updated_files_count += 1
    

if __name__ == '__main__':
    main() 