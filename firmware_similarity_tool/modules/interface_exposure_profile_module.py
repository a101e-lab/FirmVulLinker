import os
import json
import math
from collections import Counter
from modules.base_module import BaseComparisonModule
from modules.similarity_utils import calculate_combined_similarity

class InterfaceExposureProfileModule(BaseComparisonModule):
    """
    通信接口暴露画像模块 (Interface Exposure Profile Module)
    用于提取并表示固件中的外部通信路径与输入参数名称，建模其潜在的功能入口与攻击面特征
    实现基于接口路径和参数的固件相似度比较
    """
    
    def __init__(self, config):
        # 先调用父类的__init__方法
        super().__init__(config)
        # 然后明确设置name属性
        self.name = "interface_exposure"
        # 重新获取模块配置和启用状态
        self.enabled = config.is_module_enabled(self.name)
        self.module_config = config.get_module_config(self.name)
    
    def _calculate_structural_summary_vector(self, api_set, param_set):
        """
        计算结构摘要向量 [Nu, Nk, μd, H_prefix, H_key]
        """
        # Nu: 接口路径数量
        N_u = len(api_set)
        
        # Nk: 参数名称数量
        N_k = len(param_set)
        
        # μd: 平均路径深度
        mu_d = 0.0
        if N_u > 0:
            total_depth = 0
            for path in api_set:
                total_depth += path.count('/')
            mu_d = total_depth / N_u
            
        # H_prefix: 路径命名前缀熵
        H_prefix = 0.0
        if N_u > 0:
            prefixes = []
            for path in api_set:
                # 规范化路径并分割
                normalized_path = os.path.normpath(path)
                parts = normalized_path.split(os.sep)
                # 提取第一个非空的有效部分作为前缀
                # 例如，'/cgi-bin/test' -> 'cgi-bin', 'api/v1/go' -> 'api'
                # 'login.cgi' -> 'login.cgi'
                first_part = next((part for part in parts if part and part != '.'), None)
                if first_part:
                    prefixes.append(first_part)
            
            if prefixes:
                prefix_counts = Counter(prefixes)
                total_prefixes = len(prefixes)
                for count in prefix_counts.values():
                    p_j = count / total_prefixes
                    if p_j > 0:
                        H_prefix -= p_j * math.log2(p_j)
                        
        # H_key: 参数命名字符熵
        H_key = 0.0
        if param_set:
            all_param_chars_string = "".join(param_set)
            if all_param_chars_string:
                char_counts = Counter(all_param_chars_string)
                total_chars = len(all_param_chars_string)
                for count in char_counts.values():
                    p_c = count / total_chars
                    if p_c > 0:
                        H_key -= p_c * math.log2(p_c)
                        
        return [N_u, N_k, mu_d, H_prefix, H_key]

    def _calculate_structural_summary_similarity(self, vector1, vector2):
        """
        计算结构摘要向量之间的余弦相似度
        """
        dot_product = sum(v1 * v2 for v1, v2 in zip(vector1, vector2))
        
        norm1 = math.sqrt(sum(v**2 for v in vector1))
        norm2 = math.sqrt(sum(v**2 for v in vector2))
        
        if norm1 == 0 or norm2 == 0:
            return 0.0 
        return dot_product / (norm1 * norm2)

    def calculate_similarity(self, firmware1_path, firmware2_path):
        """
        计算基于通信接口暴露画像的相似度
        
        分别计算接口路径集合相似度(api_similarity)和参数名称集合相似度(param_similarity)，
        并通过加权平均得到综合相似度
        
        Args:
            firmware1_path: 第一个固件特征路径
            firmware2_path: 第二个固件特征路径
            
        Returns:
            tuple: (相似度值, 详细比较结果字典)
        """
        api_paths_templates = [
            'output_json/{firmware_dir}/keyword_extract_result/simple/API_simple.result',
            'output_json/{firmware_dir}/API_simple.result',
            'output_json/{firmware_dir}/keyword_extract_result/API_simple.result'
        ]
        param_paths_templates = [
            'output_json/{firmware_dir}/keyword_extract_result/simple/Prar_simple.result',
            'output_json/{firmware_dir}/Prar_simple.result',
            'output_json/{firmware_dir}/keyword_extract_result/Prar_simple.result'
        ]

        api_file1_path_resolved = None
        api_file2_path_resolved = None
        for path_template in api_paths_templates:
            path1 = self.get_file_path(firmware1_path, path_template)
            path2 = self.get_file_path(firmware2_path, path_template)
            if api_file1_path_resolved is None and os.path.exists(path1):
                 api_file1_path_resolved = path1
            if api_file2_path_resolved is None and os.path.exists(path2):
                 api_file2_path_resolved = path2
            if api_file1_path_resolved and api_file2_path_resolved: # check if both found to break early
                if os.path.exists(api_file1_path_resolved) and os.path.exists(api_file2_path_resolved):
                    break
        
        param_file1_path_resolved = None
        param_file2_path_resolved = None
        for path_template in param_paths_templates:
            path1 = self.get_file_path(firmware1_path, path_template)
            path2 = self.get_file_path(firmware2_path, path_template)
            if param_file1_path_resolved is None and os.path.exists(path1):
                param_file1_path_resolved = path1
            if param_file2_path_resolved is None and os.path.exists(path2):
                param_file2_path_resolved = path2
            if param_file1_path_resolved and param_file2_path_resolved: # check if both found
                if os.path.exists(param_file1_path_resolved) and os.path.exists(param_file2_path_resolved):
                    break
        
        # Fallback to func_name.txt for API files if primary API files are not found
        if not (api_file1_path_resolved and os.path.exists(api_file1_path_resolved) and \
                api_file2_path_resolved and os.path.exists(api_file2_path_resolved) ):
            func_path_template = 'output_json/{firmware_dir}/func_name.txt'
            func_file1 = self.get_file_path(firmware1_path, func_path_template)
            func_file2 = self.get_file_path(firmware2_path, func_path_template)
            
            resolved_from_func = False
            temp_api_file1 = None
            temp_api_file2 = None

            if os.path.exists(func_file1):
                temp_api_file1 = func_file1
            if os.path.exists(func_file2):
                temp_api_file2 = func_file2
            
            if temp_api_file1 and temp_api_file2: # Both func files must exist
                api_file1_path_resolved = temp_api_file1
                api_file2_path_resolved = temp_api_file2
                print(f"警告: 使用 {func_path_template} 代替 API_simple.result 进行接口路径比较")
                resolved_from_func = True
            elif not api_file1_path_resolved and temp_api_file1 : # if original api_file1 was not found, but func_file1 exists
                 api_file1_path_resolved = temp_api_file1
                 if not api_file2_path_resolved and not temp_api_file2: # if api_file2 is also missing func_file2
                     print(f"警告: 固件1使用 {func_path_template}，但固件2对应的 func_name.txt 或 API_simple.result 未找到")
                 elif api_file2_path_resolved and os.path.exists(api_file2_path_resolved): # api_file1 is func, api_file2 is original
                     print(f"警告: 固件1使用 {func_path_template}，固件2使用其找到的 API_simple.result")

            elif not api_file2_path_resolved and temp_api_file2 : # if original api_file2 was not found, but func_file2 exists
                 api_file2_path_resolved = temp_api_file2
                 if not api_file1_path_resolved and not temp_api_file1:
                     print(f"警告: 固件2使用 {func_path_template}，但固件1对应的 func_name.txt 或 API_simple.result 未找到")
                 elif api_file1_path_resolved and os.path.exists(api_file1_path_resolved):
                     print(f"警告: 固件2使用 {func_path_template}，固件1使用其找到的 API_simple.result")


        api_set1 = self._read_txt_to_set(api_file1_path_resolved) if api_file1_path_resolved and os.path.exists(api_file1_path_resolved) else set()
        api_set2 = self._read_txt_to_set(api_file2_path_resolved) if api_file2_path_resolved and os.path.exists(api_file2_path_resolved) else set()
        param_set1 = self._read_txt_to_set(param_file1_path_resolved) if param_file1_path_resolved and os.path.exists(param_file1_path_resolved) else set()
        param_set2 = self._read_txt_to_set(param_file2_path_resolved) if param_file2_path_resolved and os.path.exists(param_file2_path_resolved) else set()

        api_files_found = bool(api_file1_path_resolved and os.path.exists(api_file1_path_resolved) and \
                               api_file2_path_resolved and os.path.exists(api_file2_path_resolved))
        param_files_found = bool(param_file1_path_resolved and os.path.exists(param_file1_path_resolved) and \
                                 param_file2_path_resolved and os.path.exists(param_file2_path_resolved))

        if not api_files_found:
            print(f"警告: 无法找到成对的接口路径文件 (API_simple.result 或 func_name.txt)。已尝试的模板: {api_paths_templates} 和备选 func_name.txt")
        if not param_files_found:
            print(f"警告: 无法找到成对的参数名称文件 (Prar_simple.result)。已尝试的模板: {param_paths_templates}")

        if not api_files_found and not param_files_found:
             raise FileNotFoundError("接口路径和参数名称文件都无法成对找到，无法进行比较")

        # Sim_url: 接口路径集合相似度
        api_similarity = calculate_combined_similarity(api_set1, api_set2) if api_files_found else 0.0
        
        # Sim_key: 参数名称集合相似度
        param_similarity = calculate_combined_similarity(param_set1, param_set2) if param_files_found else 0.0
        
        # Sim_stat: 结构摘要向量相似度
        phi_intf1 = self._calculate_structural_summary_vector(api_set1, param_set1)
        phi_intf2 = self._calculate_structural_summary_vector(api_set2, param_set2)
        structural_similarity = self._calculate_structural_summary_similarity(phi_intf1, phi_intf2)
        
        # Sim_intf: 综合相似度
        # λ1, λ2, λ3 from config, assuming they sum to 1 as per paper
        lambda1 = self.module_config.get('api_weight', 1/3)
        lambda2 = self.module_config.get('param_weight', 1/3)
        lambda3 = self.module_config.get('structural_summary_weight', 1/3) # New weight
        
        overall_similarity = (api_similarity * lambda1 + 
                              param_similarity * lambda2 + 
                              structural_similarity * lambda3)
        
        common_interfaces = list(api_set1.intersection(api_set2))
        
        details = {
            "interface_file1": api_file1_path_resolved if api_files_found else None,
            "interface_file2": api_file2_path_resolved if api_files_found else None,
            "param_file1": param_file1_path_resolved if param_files_found else None,
            "param_file2": param_file2_path_resolved if param_files_found else None,
            "interface_similarity_Sim_url": api_similarity,
            "param_similarity_Sim_key": param_similarity,
            "structural_summary_vector1": phi_intf1,
            "structural_summary_vector2": phi_intf2,
            "structural_summary_similarity_Sim_stat": structural_similarity,
            "common_interfaces_count": len(common_interfaces),
            "common_interfaces_sample": common_interfaces[:100], # Show a sample
            "overall_similarity_Sim_intf": overall_similarity,
            "weights_lambda": {"api": lambda1, "param": lambda2, "structural": lambda3},
            "common_interfaces": common_interfaces # Full list
        }
        
        return overall_similarity, details
    
    def _read_txt_to_set(self, file_path):
        """
        读取文本文件，返回非空行集合
        
        Args:
            file_path: 文件路径
            
        Returns:
            set: 非空行集合
        """
        result_set = set()
        if not file_path or not os.path.exists(file_path): # Check if file_path is None or does not exist
            return result_set
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        result_set.add(line)
            return result_set
        except Exception as e:
            print(f"读取文件时出错 {file_path}: {str(e)}")
            return set()
    
    def _get_common_interfaces(self, api_file1, api_file2):
        """
        获取两个接口路径文件中的共同接口
        
        Args:
            api_file1: 第一个接口路径文件路径
            api_file2: 第二个接口路径文件路径
            
        Returns:
            list: 共同接口路径列表
        """
        api_set1 = self._read_txt_to_set(api_file1)
        api_set2 = self._read_txt_to_set(api_file2)
        
        common_apis = api_set1.intersection(api_set2)
        return list(common_apis)