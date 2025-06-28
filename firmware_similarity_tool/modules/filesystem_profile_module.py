import os
import json
import hashlib
import ssdeep
from collections import defaultdict
from datasketch import MinHash, MinHashLSHForest
import glob
from modules.base_module import BaseComparisonModule
from modules.similarity_utils import calculate_combined_similarity

class FileSystemProfileModule(BaseComparisonModule):
    """
    文件系统语义画像模块，整合多个维度分析固件相似性：
    1. 结构布局建模 - 目录结构与文件组织
    2. 敏感资源标注与建模 - 敏感信息、配置、证书等
    3. 二进制资源签名画像 - 哈希、字符串特征等
    """
    
    def __init__(self, config):
        # 先调用父类的__init__方法
        super().__init__(config)
        # 然后明确设置name属性
        self.name = "filesystem_profile"
        # 重新获取模块配置和启用状态
        self.enabled = config.is_module_enabled(self.name)
        self.module_config = config.get_module_config(self.name)
    
    def calculate_similarity(self, firmware1_path, firmware2_path):
        """
        计算基于文件系统画像的综合相似度
        
        Args:
            firmware1_path: The path to the first firmware
            firmware2_path: The path to the second firmware
            
        Returns:
            tuple: (相似度值, 详细比较结果字典)
        """
        print(f"开始分析文件系统画像 - 比较 {firmware1_path} 和 {firmware2_path}")
        
        # 获取固件目录名
        firmware1_dir = os.environ.get('FIRMWARE1_DIR', os.path.basename(firmware1_path))
        firmware2_dir = os.environ.get('FIRMWARE2_DIR', os.path.basename(firmware2_path))
        
        # 1. 结构布局建模分析
        print("1. 执行结构布局建模分析...")
        structure_similarity, structure_details = self._analyze_structural_layout(firmware1_path, firmware2_path)
        
        # 2. 敏感资源分析
        print("2. 执行敏感资源分析...")
        sensitive_similarity, sensitive_details = self._analyze_sensitive_resources(firmware1_path, firmware2_path)
        
        # 3. 二进制资源签名画像分析
        print("3. 执行二进制资源签名画像分析...")
        binary_similarity, binary_details = self._analyze_binary_signatures(firmware1_path, firmware2_path)
        
        # 获取三个维度的权重配置
        weights = {
            "structure": self.module_config.get('structure_weight', 0.3),
            "sensitive": self.module_config.get('sensitive_weight', 0.3),
            "binary": self.module_config.get('binary_weight', 0.4)
        }
        
        # 计算加权平均相似度
        total_weight = sum(weights.values())
        overall_similarity = (
            structure_similarity * weights["structure"] +
            sensitive_similarity * weights["sensitive"] +
            binary_similarity * weights["binary"]
        ) / total_weight if total_weight > 0 else 0.0
        
        # 特殊处理相同文件夹的情况
        if firmware1_path == firmware2_path:
            overall_similarity = 1.0
        
        # 准备详细结果
        details = {
            "firmware1_path": firmware1_path,
            "firmware2_path": firmware2_path,
            "firmware1_dir": firmware1_dir,
            "firmware2_dir": firmware2_dir,
            "overall_similarity": overall_similarity,
            "weights": weights,
            "structural_layout": {
                "similarity": structure_similarity,
                "details": structure_details
            },
            "sensitive_resources": {
                "similarity": sensitive_similarity,
                "details": sensitive_details
            },
            "binary_signatures": {
                "similarity": binary_similarity,
                "details": binary_details
            }
        }
        
        return overall_similarity, details
    
    def _analyze_structural_layout(self, firmware1_path, firmware2_path):
        """
        结构布局建模 - 分析目录结构与文件组织
        """
        # 获取output.json文件路径
        output_json_file1 = self.get_file_path(
            firmware1_path, 
            self.module_config.get('output_json_file1', 'output_json/{firmware_name}/output.json')
        )
        
        output_json_file2 = self.get_file_path(
            firmware2_path, 
            self.module_config.get('output_json_file2', 'output_json/{firmware_name}/output.json')
        )
        
        # 检查文件是否存在
        if not os.path.exists(output_json_file1):
            raise FileNotFoundError(f"Output JSON文件不存在: {output_json_file1}")
        if not os.path.exists(output_json_file2):
            raise FileNotFoundError(f"Output JSON文件不存在: {output_json_file2}")
        
        # 加载JSON数据
        data1 = self._load_json(output_json_file1)
        data2 = self._load_json(output_json_file2)
        
        # 比较目录结构
        directory_similarity = self._compare_directory_structure(data1, data2)
        file_set_similarity = self._compare_file_set(data1, data2)
        
        # 比较基本文件系统信息
        basic_info_similarity = self._compare_basic_info(data1, data2)
        
        # 计算结构布局的整体相似度
        structure_weights = {
            "directory": self.module_config.get('directory_weight', 0.5),
            "file_set": self.module_config.get('file_set_weight', 0.4),
            "basic_info": self.module_config.get('basic_info_weight', 0.1)
        }
        
        total_weight = sum(structure_weights.values())
        structure_similarity = (
            directory_similarity * structure_weights["directory"] +
            file_set_similarity * structure_weights["file_set"] +
            basic_info_similarity * structure_weights["basic_info"]
        ) / total_weight if total_weight > 0 else 0.0
        
        details = {
            "directory_similarity": directory_similarity,
            "file_set_similarity": file_set_similarity,
            "basic_info_similarity": basic_info_similarity,
            "structure_weights": structure_weights
        }
        
        return structure_similarity, details
    
    def _analyze_sensitive_resources(self, firmware1_path, firmware2_path):
        """
        敏感资源标注与建模 - 分析敏感信息、配置、证书等
        """
        # 获取output.json文件路径
        output_json_file1 = self.get_file_path(
            firmware1_path, 
            self.module_config.get('output_json_file1', 'output_json/{firmware_name}/output.json')
        )
        
        output_json_file2 = self.get_file_path(
            firmware2_path, 
            self.module_config.get('output_json_file2', 'output_json/{firmware_name}/output.json')
        )
        
        # 加载JSON数据
        data1 = self._load_json(output_json_file1)
        data2 = self._load_json(output_json_file2)
        
        # 比较IP地址
        ip_similarity = self._compare_ip_addresses(data1, data2)
        
        # 比较URL
        url_similarity = self._compare_urls(data1, data2)
        
        # 比较Email
        email_similarity = self._compare_emails(data1, data2)
        
        # 比较配置文件
        config_file_similarity = self._compare_configuration_files(data1, data2)
        
        # 比较CA文件和公私钥
        key_similarity, hash_similarity = self._compare_ca_file_info(data1, data2)
        keys_similarity_results, avg_file_hash_similarity, avg_private_key_similarity, avg_public_key_similarity = self._compare_public_private_keys(data1, data2)
        
        # 比较详细文件信息
        file_info_similarity = self._compare_detailed_file_info(data1, data2)
        
        # 计算敏感资源的整体相似度
        sensitive_weights = {
            "ip": self.module_config.get('ip_weight', 0.1),
            "url": self.module_config.get('url_weight', 0.1),
            "email": self.module_config.get('email_weight', 0.1),
            "config_file": self.module_config.get('config_file_weight', 0.15),
            "key": self.module_config.get('key_weight', 0.15),
            "hash": self.module_config.get('hash_weight', 0.1),
            "file_hash": self.module_config.get('file_hash_weight', 0.1),
            "file_info": self.module_config.get('file_info_weight', 0.2)
        }
        
        # 准备加权值
        weighted_scores = []
        total_weight = 0
        
        if ip_similarity is not None:
            weighted_scores.append(ip_similarity * sensitive_weights["ip"])
            total_weight += sensitive_weights["ip"]
        
        if url_similarity is not None:
            weighted_scores.append(url_similarity * sensitive_weights["url"])
            total_weight += sensitive_weights["url"]
        
        if email_similarity is not None:
            weighted_scores.append(email_similarity * sensitive_weights["email"])
            total_weight += sensitive_weights["email"]
        
        if config_file_similarity is not None:
            weighted_scores.append(config_file_similarity * sensitive_weights["config_file"])
            total_weight += sensitive_weights["config_file"]
        
        if key_similarity is not None:
            weighted_scores.append(key_similarity * sensitive_weights["key"])
            total_weight += sensitive_weights["key"]
        
        if hash_similarity is not None:
            weighted_scores.append(hash_similarity * sensitive_weights["hash"])
            total_weight += sensitive_weights["hash"]
        
        if avg_file_hash_similarity is not None:
            weighted_scores.append(avg_file_hash_similarity * sensitive_weights["file_hash"])
            total_weight += sensitive_weights["file_hash"]
        
        if file_info_similarity is not None:
            weighted_scores.append(file_info_similarity * sensitive_weights["file_info"])
            total_weight += sensitive_weights["file_info"]
        
        # 计算加权平均
        sensitive_similarity = sum(weighted_scores) / total_weight if total_weight > 0 else 0.0
        
        details = {
            "ip_similarity": ip_similarity,
            "url_similarity": url_similarity,
            "email_similarity": email_similarity,
            "config_file_similarity": config_file_similarity,
            "key_similarity": key_similarity,
            "hash_similarity": hash_similarity,
            "public_private_keys": {
                "avg_file_hash_similarity": avg_file_hash_similarity,
                "avg_private_key_similarity": avg_private_key_similarity,
                "avg_public_key_similarity": avg_public_key_similarity,
                "detailed_results": keys_similarity_results
            },
            "file_info_similarity": file_info_similarity,
            "sensitive_weights": sensitive_weights
        }
        
        return sensitive_similarity, details
    
    def _analyze_binary_signatures(self, firmware1_path, firmware2_path):
        """
        二进制资源签名画像 - 分析哈希、字符串特征等
        """
        # 1. 分析二进制文件哈希相似度
        hash_similarity, hash_details = self._analyze_binary_hash(firmware1_path, firmware2_path)
        
        # 2. 分析字符串名称相似度
        string_similarity, string_details = self._analyze_string_similarity(firmware1_path, firmware2_path)
        
        # 3. 分析所有字符串文件相似度
        allstrings_similarity, allstrings_details = self._analyze_all_strings(firmware1_path, firmware2_path)
        
        # 4. 分析二进制文件信息
        bin_file_similarity = self._analyze_bin_files(firmware1_path, firmware2_path)
        
        # 计算二进制签名的整体相似度
        binary_weights = {
            "hash": self.module_config.get('binary_hash_weight', 0.3),
            "string": self.module_config.get('string_weight', 0.2),
            "allstrings": self.module_config.get('allstrings_weight', 0.3),
            "bin_file": self.module_config.get('bin_file_weight', 0.2)
        }
        
        # 准备加权值
        weighted_scores = []
        total_weight = 0
        
        if hash_similarity is not None:
            weighted_scores.append(hash_similarity * binary_weights["hash"])
            total_weight += binary_weights["hash"]
        
        if string_similarity is not None:
            weighted_scores.append(string_similarity * binary_weights["string"])
            total_weight += binary_weights["string"]
        
        if allstrings_similarity is not None:
            weighted_scores.append(allstrings_similarity * binary_weights["allstrings"])
            total_weight += binary_weights["allstrings"]
        
        if bin_file_similarity is not None:
            weighted_scores.append(bin_file_similarity * binary_weights["bin_file"])
            total_weight += binary_weights["bin_file"]
        
        # 计算加权平均
        binary_similarity = sum(weighted_scores) / total_weight if total_weight > 0 else 0.0
        
        details = {
            "hash_similarity": hash_similarity,
            "hash_details": hash_details,
            "string_similarity": string_similarity,
            "string_details": string_details,
            "allstrings_similarity": allstrings_similarity,
            "allstrings_details": allstrings_details,
            "bin_file_similarity": bin_file_similarity,
            "binary_weights": binary_weights
        }
        
        return binary_similarity, details
    
    def _analyze_binary_hash(self, firmware1_path, firmware2_path):
        """
        分析二进制文件哈希相似度 (从HashModule复用)
        """
        # 计算文件的哈希值
        hash_results1 = self._calculate_hash(firmware1_path)
        hash_results2 = self._calculate_hash(firmware2_path)
        
        # 获取相似度阈值
        similarity_threshold = self.module_config.get('similarity_threshold', 50)
        
        # 计算相似度（同时使用精确匹配和模糊匹配）
        exact_matches, similar_files, total_comparison = self._compare_hash_results(
            hash_results1, hash_results2, similarity_threshold)
        
        # 获取权重配置，用于计算综合相似度
        match_weight = self.module_config.get('match_weight', 0.5)
        sim_weight = self.module_config.get('sim_weight', 0.5)
        
        # 计算精确匹配和模糊匹配的相似度
        exact_similarity = len(exact_matches) / total_comparison if total_comparison > 0 else 0
        fuzzy_similarity = sum(item["similarity"] for item in similar_files) / (total_comparison * 100) if total_comparison > 0 else 0
        
        # 计算综合相似度
        overall_similarity = (exact_similarity * match_weight) + (fuzzy_similarity * sim_weight)
        
        # 特殊处理相同文件夹
        if firmware1_path == firmware2_path and hash_results1 and hash_results1 == hash_results2:
            overall_similarity = 1.0
        
        # 准备详细结果
        details = {
            "exact_matches_count": len(exact_matches),
            "similar_files_count": len(similar_files),
            "total_comparison": total_comparison,
            "exact_similarity": exact_similarity,
            "fuzzy_similarity": fuzzy_similarity,
            "similarity_threshold": similarity_threshold,
            "exact_matches": exact_matches[:20] if len(exact_matches) > 20 else exact_matches,
            "similar_files": similar_files[:20] if len(similar_files) > 20 else similar_files
        }
        
        return overall_similarity, details
    
    def _analyze_string_similarity(self, firmware1_path, firmware2_path):
        """
        分析字符串名称相似度 (从StringModule复用)
        """
        # 获取字符串文件路径
        string_file1 = self.get_file_path(
            firmware1_path, 
            self.module_config.get('string_file1', 'output_json/{firmware_name}/string_name.txt')
        )
        
        string_folder2 = self.get_file_path(
            firmware2_path, 
            self.module_config.get('string_folder2', 'output_json/{firmware_name}')
        )
        
        string_file2 = os.path.join(string_folder2, 'string_name.txt')
        
        # 检查文件是否存在
        if not os.path.exists(string_file1):
            print(f"警告: 字符串文件不存在: {string_file1}")
            return 0.0, {"error": f"字符串文件不存在: {string_file1}"}
        if not os.path.exists(string_file2):
            print(f"警告: 字符串文件不存在: {string_file2}")
            return 0.0, {"error": f"字符串文件不存在: {string_file2}"}
        
        # 计算字符串相似度
        similarity, common_strings = self._calculate_string_similarity(string_file1, string_file2)
        
        # 准备详细结果
        details = {
            "string_file1": string_file1,
            "string_file2": string_file2,
            "similarity": similarity,
            "num_perm": self.module_config.get('num_perm', 128),
            "common_strings_count": len(common_strings),
            "common_strings_sample": common_strings[:100] if len(common_strings) > 100 else common_strings
        }
        
        return similarity, details
    
    def _analyze_all_strings(self, firmware1_path, firmware2_path):
        """
        分析所有字符串文件相似度 (从AllStringsModule复用)
        """
        # 获取固件目录名
        firmware1_dir = os.environ.get('FIRMWARE1_DIR', os.path.basename(firmware1_path))
        firmware2_dir = os.environ.get('FIRMWARE2_DIR', os.path.basename(firmware2_path))
        
        # 从配置中获取字符串文件夹路径模板
        strings_folder1_template = self.module_config.get(
            'strings_folder1',
            "output_json/{firmware_dir}/{firmware_dir}_all_strings"
        )
        strings_folder2_template = self.module_config.get(
            'strings_folder2',
            "output_json/{firmware_dir}/{firmware_dir}_all_strings"
        )
        
        # 构建实际路径
        strings_folder1 = self.get_file_path(firmware1_path, strings_folder1_template)
        strings_folder2 = self.get_file_path(firmware2_path, strings_folder2_template)
        
        # 检查目录是否存在
        if not os.path.exists(strings_folder1) or not os.path.isdir(strings_folder1):
            print(f"警告: 字符串文件夹不存在: {strings_folder1}")
            return 0.0, {"error": f"字符串文件夹不存在: {strings_folder1}"}
        if not os.path.exists(strings_folder2) or not os.path.isdir(strings_folder2):
            print(f"警告: 字符串文件夹不存在: {strings_folder2}")
            return 0.0, {"error": f"字符串文件夹不存在: {strings_folder2}"}
        
        # 读取并分类所有字符串文件
        strings_files1 = self._get_strings_files(strings_folder1)
        strings_files2 = self._get_strings_files(strings_folder2)
        
        # 按照文件类型进行分组
        grouped_files1 = self._group_by_type(strings_files1)
        grouped_files2 = self._group_by_type(strings_files2)
        
        # 对每个组进行比较
        group_results = {}
        weighted_similarities = []
        total_weight = 0
        
        # 尝试比较公共组
        for group_name in set(grouped_files1.keys()).intersection(grouped_files2.keys()):
            files1 = grouped_files1[group_name]
            files2 = grouped_files2[group_name]
            
            # 对该组的文件进行比较
            result, similarity = self._compare_file_group(files1, files2, group_name)
            group_results[group_name] = result
            # 使用加权相似度
            weighted_similarities.append(result["weighted_similarity"])
            total_weight += result["weight"]
        
        # 尝试比较功能相似的文件，通过文件名的相似性来判断
        similar_files_results = self._find_similar_files(grouped_files1, grouped_files2)
        for result in similar_files_results:
            if result["group"] not in group_results:  # 避免重复比较
                group_results[result["group"]] = result
                weighted_similarities.append(result["weighted_similarity"])
                total_weight += result["weight"]
        
        # 计算总体相似度（加权平均）
        if not weighted_similarities:
            overall_similarity = 0.0
        else:
            overall_similarity = sum(weighted_similarities) / total_weight if total_weight > 0 else 0.0
        
        # 准备详细结果
        details = {
            "strings_folder1": strings_folder1,
            "strings_folder2": strings_folder2,
            "group_count": len(group_results),
            "overall_similarity": overall_similarity,
            "group_results": group_results
        }
        
        return overall_similarity, details
    
    def _analyze_bin_files(self, firmware1_path, firmware2_path):
        """
        分析二进制文件信息
        """
        # 获取output.json文件路径
        output_json_file1 = self.get_file_path(
            firmware1_path, 
            self.module_config.get('output_json_file1', 'output_json/{firmware_name}/output.json')
        )
        
        output_json_file2 = self.get_file_path(
            firmware2_path, 
            self.module_config.get('output_json_file2', 'output_json/{firmware_name}/output.json')
        )
        
        # 加载JSON数据
        data1 = self._load_json(output_json_file1)
        data2 = self._load_json(output_json_file2)
        
        # 比较二进制文件信息
        bin_files1 = set(data1.get("bin_file_info", []))
        bin_files2 = set(data2.get("bin_file_info", []))
        
        return calculate_combined_similarity(bin_files1, bin_files2)
    
    # 以下是从FilesModule复用的方法
    def _load_json(self, file_path):
        """加载JSON文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"无法解析JSON文件 {file_path}: {str(e)}")
    
    def _compare_directory_structure(self, data1, data2):
        """比较两个JSON文件中的directory_structure_info列表，使用综合相似度"""
        directory_structure_info1 = set(data1.get("directory_structure_info", []))
        directory_structure_info2 = set(data2.get("directory_structure_info", []))
        
        return calculate_combined_similarity(directory_structure_info1, directory_structure_info2)
    
    def _compare_file_set(self, data1, data2):
        """比较两个JSON数据中的file_set列表，使用综合相似度"""
        file_set1 = set(data1.get("file_set", []))
        file_set2 = set(data2.get("file_set", []))
        
        return calculate_combined_similarity(file_set1, file_set2)
    
    def _compare_basic_info(self, data1, data2):
        """比较两个JSON数据中的基本固件信息"""
        # 获取基本信息字段
        basic_fields = ["architecture", "filesystem", "operating_system"]
        
        matches = 0
        total = len(basic_fields)
        
        for field in basic_fields:
            value1 = data1.get(field, "")
            value2 = data2.get(field, "")
            
            if value1 == value2 and value1:  
                matches += 1
        
        # 计算匹配率
        return matches / total if total > 0 else 0.0
    
    def _compare_ip_addresses(self, data1, data2):
        """比较两个JSON数据中的IP地址列表"""
        ip_addresses1 = set(data1.get("ip_addresses", []))
        ip_addresses2 = set(data2.get("ip_addresses", []))
        
        return calculate_combined_similarity(ip_addresses1, ip_addresses2)
    
    def _compare_urls(self, data1, data2):
        """比较两个JSON数据中的URL列表"""
        urls1 = set(data1.get("urls", []))
        urls2 = set(data2.get("urls", []))
        
        return calculate_combined_similarity(urls1, urls2)
    
    def _compare_emails(self, data1, data2):
        """比较两个JSON数据中的邮箱列表"""
        emails1 = set(data1.get("emails", []))
        emails2 = set(data2.get("emails", []))
        
        return calculate_combined_similarity(emails1, emails2)
    
    def _compare_configuration_files(self, data1, data2):
        """比较两个JSON数据中的配置文件信息"""
        config_files1 = set(data1.get("configuration_file_info", []))
        config_files2 = set(data2.get("configuration_file_info", []))
        
        return calculate_combined_similarity(config_files1, config_files2)
    
    def _compare_ca_file_info(self, data1, data2):
        """比较两个JSON文件中的ca_file_hashes字段"""
        ca_file_hashes1 = data1.get("ca_file_hashes", {})
        ca_file_hashes2 = data2.get("ca_file_hashes", {})
        
        if not ca_file_hashes1 and not ca_file_hashes2:
            return 0.0, 0.0
        
        # 计算键的相似度
        keys1 = set(ca_file_hashes1.keys())
        keys2 = set(ca_file_hashes2.keys())
        key_similarity = calculate_combined_similarity(keys1, keys2)
        
        # 计算哈希值的相似度
        all_hashes1 = set(ca_file_hashes1.values())
        all_hashes2 = set(ca_file_hashes2.values())
        hash_similarity = calculate_combined_similarity(all_hashes1, all_hashes2)
        
        return key_similarity, hash_similarity
    
    def _compare_public_private_keys(self, data1, data2):
        """比较两个JSON数据中的public_private_key字段"""
        keys1 = data1.get("public_private_key", {})
        keys2 = data2.get("public_private_key", {})
        
        # 如果键完全相同，直接返回1.0
        if keys1 == keys2 and keys1:
            return [], 1.0, 1.0, 1.0
        
        # 为空时返回默认值
        if not keys1 or not keys2:
            return [], 0.0, 0.0, 0.0
        
        # 比较每个键值对，而不是所有组合
        common_keys = set(keys1.keys()).intersection(set(keys2.keys()))
        total_keys = len(set(keys1.keys()).union(set(keys2.keys())))
        
        similarity_results = []
        total_file_hash_sim = 0
        total_private_key_sim = 0
        total_public_key_sim = 0
        
        for key in common_keys:
            items1 = keys1[key]
            items2 = keys2[key]
            
            if items1 == items2:  # 完全相同
                total_file_hash_sim += 1
                total_private_key_sim += 1
                total_public_key_sim += 1
                similarity_results.append({
                    "key": key,
                    "file_hash_similarity": 1.0,
                    "private_key_similarity": 1.0,
                    "public_key_similarity": 1.0
                })
            else:
                # 检查文件哈希是否匹配
                file_hash_sim = 0.0
                private_key_sim = 0.0
                public_key_sim = 0.0
                
                if isinstance(items1, list) and isinstance(items2, list) and len(items1) >= 3 and len(items2) >= 3:
                    # 检查文件哈希
                    file_hash1 = items1[0].get("file_hash") if isinstance(items1[0], dict) else None
                    file_hash2 = items2[0].get("file_hash") if isinstance(items2[0], dict) else None
                    if file_hash1 is not None and file_hash1 == file_hash2:
                        file_hash_sim = 1.0
                    
                    # 检查私钥
                    private_key1 = items1[1].get("private_key") if isinstance(items1[1], dict) else None
                    private_key2 = items2[1].get("private_key") if isinstance(items2[1], dict) else None
                    if private_key1 and private_key2 and private_key1 == private_key2:
                        private_key_sim = 1.0
                    
                    # 检查公钥
                    public_key1 = items1[2].get("public_key") if isinstance(items1[2], dict) else None
                    public_key2 = items2[2].get("public_key") if isinstance(items2[2], dict) else None
                    if public_key1 and public_key2 and public_key1 == public_key2:
                        public_key_sim = 1.0
                
                total_file_hash_sim += file_hash_sim
                total_private_key_sim += private_key_sim
                total_public_key_sim += public_key_sim
                
                similarity_results.append({
                    "key": key,
                    "file_hash_similarity": file_hash_sim,
                    "private_key_similarity": private_key_sim,
                    "public_key_similarity": public_key_sim
                })
        
        # 计算平均相似度
        avg_file_hash_sim = total_file_hash_sim / total_keys if total_keys > 0 else 0.0
        avg_private_key_sim = total_private_key_sim / total_keys if total_keys > 0 else 0.0
        avg_public_key_sim = total_public_key_sim / total_keys if total_keys > 0 else 0.0
        
        return similarity_results, avg_file_hash_sim, avg_private_key_sim, avg_public_key_sim
    
    def _compare_detailed_file_info(self, data1, data2):
        """比较两个JSON数据中的file_info下的详细信息"""
        file_info1 = data1.get("file_info", {})
        file_info2 = data2.get("file_info", {})
        
        if not file_info1 or not file_info2:
            return 0.0
        
        categories = [
            "password files",
            "SSL related files",
            "SSH related files",
            "files",
            "database related files",
            "shell scripts",
            "other .bin files",
            "patterns in files",
            "web servers",
            "important binaries"
        ]
        
        category_similarities = []
        
        for category in categories:
            # 获取每个类别下的数据
            category_data1 = file_info1.get(category, {})
            category_data2 = file_info2.get(category, {})
            
            if not category_data1 and not category_data2:
                continue
            
            # 根据数据结构处理
            if isinstance(category_data1, dict) and isinstance(category_data2, dict):
                # 比较键的相似度
                keys1 = set(category_data1.keys())
                keys2 = set(category_data2.keys())
                keys_similarity = calculate_combined_similarity(keys1, keys2)
                
                # 比较值的相似度
                values_similarity_sum = 0
                value_count = 0
                common_keys = keys1.intersection(keys2)
                
                for key in common_keys:
                    value1 = category_data1[key]
                    value2 = category_data2[key]
                    
                    # 处理字符串或列表类型的值
                    if isinstance(value1, str) and isinstance(value2, str):
                        if value1 and value2:  # 非空
                            values1 = set(value1.split('\n'))
                            values2 = set(value2.split('\n'))
                            similarity = calculate_combined_similarity(values1, values2)
                            values_similarity_sum += similarity
                            value_count += 1
                    elif isinstance(value1, list) and isinstance(value2, list):
                        similarity = calculate_combined_similarity(set(value1), set(value2))
                        values_similarity_sum += similarity
                        value_count += 1
                
                # 计算该类别的平均相似度
                values_similarity = values_similarity_sum / value_count if value_count > 0 else 0
                category_similarity = (keys_similarity + values_similarity) / 2
            else:
                # 如果是简单类型，直接计算相似度
                items1 = set(str(category_data1).split('\n')) if isinstance(category_data1, str) else set()
                items2 = set(str(category_data2).split('\n')) if isinstance(category_data2, str) else set()
                category_similarity = calculate_combined_similarity(items1, items2)
            
            category_similarities.append(category_similarity)
        
        # 返回所有类别的平均相似度
        return sum(category_similarities) / len(category_similarities) if category_similarities else 0.0
    
    # 以下是从HashModule复用的方法
    def _calculate_hash(self, firmware_path):
        """
        计算固件文件的哈希值和ssdeep模糊哈希
        """
        # 计算哈希值
        hash_results = {}
        firmware_dir = os.path.abspath(firmware_path)
        
        # 检查固件目录是否存在
        if not os.path.exists(firmware_dir):
            print(f"固件目录不存在: {firmware_dir}")
            return hash_results
        
        # 遍历整个固件目录
        binary_file_count = 0
        total_file_count = 0
        
        for root, _, files in os.walk(firmware_dir):
            for file in files:
                total_file_count += 1
                file_path = os.path.join(root, file)
                
                # 检查是否为二进制文件
                if self._should_hash_file(file_path):
                    binary_file_count += 1
                    
                    # 获取相对路径，找到squashfs-root后的部分
                    rel_path = os.path.relpath(file_path, firmware_dir)
                    normalized_path = self._normalize_path(rel_path)
                    
                    try:
                        # 计算常规哈希值
                        file_hash = self._calculate_file_hash(file_path)
                        # 计算ssdeep模糊哈希
                        ssdeep_hash = self._calculate_ssdeep_hash(file_path)
                        
                        if file_hash and ssdeep_hash:
                            hash_results[normalized_path] = {
                                "md5": file_hash,
                                "ssdeep": ssdeep_hash,
                                "file_path": file_path,
                                "orig_rel_path": rel_path
                            }
                    except Exception as e:
                        print(f"计算文件哈希出错: {file_path}, {str(e)}")
        
        print(f"总文件数: {total_file_count}, 二进制文件数: {binary_file_count}")
        
        return hash_results
    
    def _normalize_path(self, path):
        """
        标准化路径，去除路径前的提取目录部分
        只保留squashfs-root/之后的部分
        """
        parts = path.split(os.sep)
        
        # 寻找squashfs-root的位置
        try:
            idx = parts.index('squashfs-root')
            # 返回squashfs-root及之后的路径
            return os.path.join(*parts[idx:])
        except ValueError:
            # 如果找不到squashfs-root，则返回原路径
            return path
    
    def _should_hash_file(self, file_path):
        """
        判断是否应该对文件进行哈希，仅对二进制文件进行哈希计算
        """
        # 判断文件是否为二进制文件
        if os.path.isfile(file_path):
            return self._is_binary_file(file_path)
        return False
    
    def _calculate_file_hash(self, file_path, chunk_size=8192):
        """
        计算文件的哈希值
        """
        # 获取配置的哈希算法
        hash_algorithm = self.module_config.get('hash_algorithm', 'md5').lower()
        
        # 选择哈希算法
        if hash_algorithm == 'sha1':
            hash_func = hashlib.sha1()
        elif hash_algorithm == 'sha256':
            hash_func = hashlib.sha256()
        else:  # 默认使用MD5
            hash_func = hashlib.md5()
        
        # 计算文件哈希值
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(chunk_size), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            print(f"读取文件出错: {file_path}, {str(e)}")
            return None
    
    def _calculate_ssdeep_hash(self, file_path):
        """
        计算文件的ssdeep模糊哈希值
        """
        try:
            # 读取文件内容并计算ssdeep哈希
            with open(file_path, 'rb') as f:
                file_data = f.read()
                if file_data:
                    return ssdeep.hash(file_data)
            return None
        except Exception as e:
            print(f"计算ssdeep哈希出错: {file_path}, {str(e)}")
            return None
    
    def _is_binary_file(self, file_path):
        """
        判断文件是否为二进制文件。
        """
        try:
            with open(file_path, 'rb') as file:
                for byte in file.read(1024):
                    if byte > 127:
                        return True
            return False
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return False
    
    def _compare_hash_results(self, hash_results1, hash_results2, similarity_threshold):
        """
        比较两个哈希结果，同时考虑精确匹配和模糊匹配
        """
        # 处理特殊情况：完全相同的哈希结果
        if hash_results1 == hash_results2 and hash_results1:
            exact_matches = [{"file1": info.get("orig_rel_path", path), 
                            "file2": info.get("orig_rel_path", path), 
                            "hash": info["md5"]} 
                            for path, info in hash_results1.items() if "md5" in info]
            return exact_matches, [], len(hash_results1)
        
        exact_matches = []
        
        # 提取文件路径和哈希值
        paths1 = set(hash_results1.keys())
        paths2 = set(hash_results2.keys())
        
        # 检查文件路径相同且MD5哈希相同的情况（精确匹配）
        common_paths = paths1.intersection(paths2)
        exact_match_paths = set()  # 记录已经精确匹配的路径
        
        for path in common_paths:
            if ("md5" in hash_results1[path] and 
                "md5" in hash_results2[path] and 
                hash_results1[path]["md5"] == hash_results2[path]["md5"]):
                
                # 使用原始相对路径作为文件标识
                file1_path = hash_results1[path].get("orig_rel_path", path)
                file2_path = hash_results2[path].get("orig_rel_path", path)
                
                exact_matches.append({
                    "file1": file1_path,
                    "file2": file2_path,
                    "hash": hash_results1[path]["md5"]
                })
                exact_match_paths.add(path)  # 添加到已匹配集合
        
        # 对文件进行ssdeep模糊哈希比较，每个文件只保留最相似的匹配
        best_matches_for_file1 = {}  # {file1_path: (file2_path, similarity, ssdeep1, ssdeep2)}
        
        for path1 in paths1:
            # 跳过已经精确匹配的文件
            if path1 in exact_match_paths:
                continue
            
            best_similarity = similarity_threshold  # 初始阈值
            best_match = None
            
            for path2 in paths2:
                # 跳过已经精确匹配的文件
                if path2 in exact_match_paths:
                    continue
                
                # 计算ssdeep相似度
                if "ssdeep" in hash_results1[path1] and "ssdeep" in hash_results2[path2]:
                    try:
                        ssdeep1 = hash_results1[path1]["ssdeep"]
                        ssdeep2 = hash_results2[path2]["ssdeep"]
                        
                        if ssdeep1 and ssdeep2:
                            similarity = ssdeep.compare(ssdeep1, ssdeep2)
                            
                            # 更新最佳匹配
                            if similarity > best_similarity:
                                best_similarity = similarity
                                best_match = (path2, similarity, ssdeep1, ssdeep2)
                    except Exception as e:
                        print(f"比较ssdeep哈希出错: {path1} - {path2}, {str(e)}")
            
            # 如果找到了最佳匹配，则记录下来
            if best_match:
                best_matches_for_file1[path1] = best_match
        
        file2_to_file1s = {}  # {file2_path: [(file1_path, similarity), ...]}
        
        for file1, (file2, similarity, _, _) in best_matches_for_file1.items():
            if file2 not in file2_to_file1s:
                file2_to_file1s[file2] = []
            file2_to_file1s[file2].append((file1, similarity))
        
        final_matches = {}  # {file1: (file2, similarity, ssdeep1, ssdeep2)}
        
        for file2, file1_list in file2_to_file1s.items():
            # 按相似度降序排序
            file1_list.sort(key=lambda x: x[1], reverse=True)
            # 保留相似度最高的匹配
            best_file1 = file1_list[0][0]
            final_matches[best_file1] = best_matches_for_file1[best_file1]
        
        # 创建最终的相似文件列表
        similar_files = [
            {
                "file1": file1,
                "file2": data[0],
                "similarity": data[1],
                "ssdeep1": data[2],
                "ssdeep2": data[3]
            }
            for file1, data in final_matches.items()
        ]
        
        # 计算总比较次数（取两个固件中文件数量的最大值）
        total_comparison = max(len(hash_results1), len(hash_results2))
        
        return exact_matches, similar_files, total_comparison
    
    # 以下是从StringModule复用的方法
    def _calculate_string_similarity(self, string_file1, string_file2):
        """
        计算两个字符串文件的相似度
        """
        # 读取字符串文件
        strings1 = self._read_txt_file(string_file1)
        strings2 = self._read_txt_file(string_file2)
        
        # 使用MinHash计算相似度
        num_perm = self.module_config.get('num_perm', 128)
        minhash1 = self._compute_minhash(strings1, num_perm)
        minhash2 = self._compute_minhash(strings2, num_perm)
        
        # 计算Jaccard相似度
        similarity = minhash1.jaccard(minhash2)
        
        # 找出共同字符串
        common_strings = list(set(strings1).intersection(set(strings2)))
        
        return similarity, common_strings
    
    def _read_txt_file(self, file_path):
        """
        读取文本文件，返回非空行列表
        """
        result = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        result.append(line)
            return result
        except Exception as e:
            print(f"读取文件时出错 {file_path}: {str(e)}")
            return []
    
    def _compute_minhash(self, strings, num_perm=128):
        """
        计算字符串列表的MinHash
        """
        minhash = MinHash(num_perm=num_perm)
        for s in strings:
            minhash.update(s.encode('utf8'))
        return minhash
    
    # 以下是从AllStringsModule复用的方法
    def _get_strings_files(self, folder_path):
        """
        获取目录下所有以_strings.txt结尾的文件
        """
        return glob.glob(os.path.join(folder_path, "*_strings.txt"))
    
    def _group_by_type(self, file_paths):
        """
        根据文件路径将文件分组
        """
        grouped = defaultdict(list)
        
        for file_path in file_paths:
            file_name = os.path.basename(file_path)
            
            # 基于文件名提取类型
            if file_name.startswith("bin_"):
                group = "bin"
            elif file_name.startswith("etc_"):
                if "events_" in file_name:
                    group = "etc_events"
                elif "scripts_" in file_name:
                    group = "etc_scripts" 
                elif "services_" in file_name:
                    group = "etc_services"
                elif "ath_" in file_name:
                    group = "etc_ath"
                else:
                    group = "etc_other"
            elif file_name.startswith("lib_"):
                if "iptables_" in file_name:
                    group = "lib_iptables"
                else:
                    group = "lib_other"
            elif file_name.startswith("www_") or file_name.startswith("htdocs_"):
                group = "web"
            elif file_name.startswith("usr_"):
                group = "usr"
            elif file_name.startswith("sbin_"):
                group = "sbin"
            else:
                group = "other"
            
            grouped[group].append(file_path)
        
        return grouped
    
    def _compare_file_group(self, files1, files2, group_name):
        """
        比较两组文件的相似度
        """
        # 读取所有文件内容
        content_set1 = set()
        content_set2 = set()
        
        for file_path in files1:
            content = self._read_strings_file(file_path)
            content_set1.update(content)
        
        for file_path in files2:
            content = self._read_strings_file(file_path)
            content_set2.update(content)
        
        # 计算交集和并集
        intersection = content_set1.intersection(content_set2)
        union = content_set1.union(content_set2)
        
        # 计算Jaccard相似度
        similarity = len(intersection) / len(union) if union else 0.0
        
        # 获取组权重
        group_weights = self.module_config.get('group_weights', {})
        weight = group_weights.get(group_name, 1.0)
        
        # 准备详细结果
        result = {
            "group": group_name,
            "files1_count": len(files1),
            "files2_count": len(files2),
            "unique_strings1": len(content_set1),
            "unique_strings2": len(content_set2),
            "common_strings": len(intersection),
            "similarity": similarity,
            "weight": weight,
            "weighted_similarity": similarity * weight,
            "common_strings_sample": list(intersection)[:100] if len(intersection) > 100 else list(intersection)
        }
        
        return result, similarity
    
    def _find_similar_files(self, grouped_files1, grouped_files2):
        """
        找出两个固件中可能相似但分组不同的文件
        """
        results = []
        
        # 获取还没有比较过的组
        remaining_groups1 = set(grouped_files1.keys()) - set(grouped_files2.keys())
        remaining_groups2 = set(grouped_files2.keys()) - set(grouped_files1.keys())
        
        # 对每一个未比较的组，尝试找出最相似的文件
        for group1 in remaining_groups1:
            best_match = None
            best_weighted_similarity = 0
            
            for group2 in remaining_groups2:
                # 比较组名相似度
                name_similarity = self._calculate_name_similarity(group1, group2)
                
                if name_similarity > 0.5:  # 只比较名称相似的组
                    result, _ = self._compare_file_group(
                        grouped_files1[group1], 
                        grouped_files2[group2],
                        f"{group1}_{group2}"
                    )
                    
                    weighted_similarity = result.get("weighted_similarity", 0)
                    if weighted_similarity > best_weighted_similarity:
                        best_weighted_similarity = weighted_similarity
                        best_match = result
            
            if best_match:
                results.append(best_match)
                group_name_parts = best_match["group"].split("_")
                if len(group_name_parts) > 1 and group_name_parts[-1] in remaining_groups2:
                    remaining_groups2.remove(group_name_parts[-1])  # 避免重复匹配
        
        return results
    
    def _calculate_name_similarity(self, name1, name2):
        """
        计算两个名称的相似度（简单的词组匹配）
        """
        words1 = set(name1.lower().split("_"))
        words2 = set(name2.lower().split("_"))
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union) if union else 0.0
    
    def _read_strings_file(self, file_path):
        """
        读取字符串文件内容
        """
        # 从配置中获取最小字符串长度
        min_string_length = self.module_config.get('min_string_length', 4)
        
        strings = set()
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and len(line) >= min_string_length:  # 忽略过短的字符串
                        strings.add(line)
            return strings
        except Exception as e:
            print(f"读取字符串文件时出错 {file_path}: {str(e)}")
            return set() 