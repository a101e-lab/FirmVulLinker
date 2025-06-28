import hashlib

def compare_file_hashes(file_paths):
    hash_values = {}
    
    # 计算每个文件的哈希值并存储在字典中
    for file_path in file_paths:
        with open(file_path, "rb") as file:
            file_content = file.read()
            hash_object = hashlib.sha256()
            hash_object.update(file_content)
            hash_value = hash_object.hexdigest()
            hash_values[file_path] = hash_value
    
    # 比较文件的哈希值
    for path1 in file_paths:
        for path2 in file_paths:
            if path1 != path2:
                if hash_values[path1] == hash_values[path2]:
                    print(f"文件 {path1} 与文件 {path2} 的哈希值相同")
                else:
                    print(f"文件 {path1} 与文件 {path2} 的哈希值不同")

# 要比较的文件路径
file_paths = ["/root/firmware_analysis_tool/binwalk_docker_result/binwalk_sig_logs/signatures_dic.json", "/root/firmware_analysis_tool/binwalk_docker_result/binwalk_sig_logs/signatures_dic_4.json", "/root/firmware_analysis_tool/binwalk_docker_result/binwalk_sig_logs/signatures_dic_3.json"]

# 调用函数比较文件的哈希值
compare_file_hashes(file_paths)
