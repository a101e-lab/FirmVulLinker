import os
import glob
import json
from collections import defaultdict
from modules.base_module import BaseComparisonModule
from datetime import datetime

class GhidraModule(BaseComparisonModule):
    """
    实现基于Ghidra分析结果的固件相似度比较
    """
    
    def __init__(self, config):
        super().__init__(config)
    
    def calculate_similarity(self, firmware1_path, firmware2_path):
        """
        计算基于Ghidra分析结果的相似度
        
        Args:
            firmware1_path: 第一个固件特征路径
            firmware2_path: 第二个固件特征路径
            
        Returns:
            tuple: (相似度值, 详细比较结果字典)
        """
        # 获取Ghidra结果目录路径
        ghidra_folder1 = self.get_file_path(
            firmware1_path, 
            self.module_config.get('ghidra_folder1', 'output_json/{firmware_dir}')
        )
        
        ghidra_folder2 = self.get_file_path(
            firmware2_path, 
            self.module_config.get('ghidra_folder2', 'output_json/{firmware_dir}')
        )
        
        # 检查目录是否存在
        if not os.path.exists(ghidra_folder1) or not os.path.isdir(ghidra_folder1):
            raise FileNotFoundError(f"Ghidra结果目录不存在: {ghidra_folder1}")
        if not os.path.exists(ghidra_folder2) or not os.path.isdir(ghidra_folder2):
            raise FileNotFoundError(f"Ghidra结果目录不存在: {ghidra_folder2}")
        
        # 获取四种结果文件：exports, imports, symbols, funcs
        exports_similarity = self._compare_ghidra_results(
            ghidra_folder1, ghidra_folder2, 
            'exports.txt', 'exports.txt', 
            self.module_config.get('exports_weight', 1.0)
        )
        
        imports_similarity = self._compare_ghidra_results(
            ghidra_folder1, ghidra_folder2, 
            'imports.txt', 'imports.txt', 
            self.module_config.get('imports_weight', 1.0)
        )
        
        symbols_similarity = self._compare_ghidra_results(
            ghidra_folder1, ghidra_folder2, 
            'symbol_name.txt', 'symbol_name.txt', 
            self.module_config.get('symbols_weight', 1.0)
        )
        
        funcs_similarity = self._compare_ghidra_results(
            ghidra_folder1, ghidra_folder2, 
            'func_name.txt', 'func_name.txt', 
            self.module_config.get('funcs_weight', 1.0)
        )
        
        # 计算综合相似度
        similarities = [
            s["weighted_similarity"] for s in 
            [exports_similarity, imports_similarity, symbols_similarity, funcs_similarity] 
            if s is not None
        ]
        
        if not similarities:
            # 如果没有任何有效的相似度结果，返回0
            return 0.0, {
                "ghidra_folder1": ghidra_folder1,
                "ghidra_folder2": ghidra_folder2,
                "error": "没有找到任何可比较的Ghidra结果文件"
            }
        
        total_weight = sum([s["weight"] for s in 
                         [exports_similarity, imports_similarity, symbols_similarity, funcs_similarity] 
                         if s is not None])
        
        overall_similarity = sum(similarities) / total_weight if total_weight > 0 else 0.0
        
        # 准备详细结果
        details = {
            "ghidra_folder1": ghidra_folder1,
            "ghidra_folder2": ghidra_folder2,
            "exports_similarity": exports_similarity,
            "imports_similarity": imports_similarity,
            "symbols_similarity": symbols_similarity,
            "funcs_similarity": funcs_similarity,
            "overall_similarity": overall_similarity
        }
        
        return overall_similarity, details
    
    def _compare_ghidra_results(self, folder1, folder2, file_pattern1, file_pattern2, weight=1.0):
        """
        比较两个Ghidra结果文件的相似度
        
        Args:
            folder1: 第一个Ghidra结果目录
            folder2: 第二个Ghidra结果目录
            file_pattern1: 第一个文件模式
            file_pattern2: 第二个文件模式
            weight: 权重
            
        Returns:
            dict: 相似度结果字典或None（如果文件不存在）
        """
        # 找到匹配的文件
        file1 = os.path.join(folder1, file_pattern1)
        file2 = os.path.join(folder2, file_pattern2)
        
        if not os.path.exists(file1) or not os.path.exists(file2):
            print(f"警告: 未找到匹配的Ghidra结果文件: {file1} 或 {file2}")
            return None
        
        # 读取文件内容
        content1 = self._read_txt_file(file1)
        content2 = self._read_txt_file(file2)
        
        if not content1 or not content2:
            print(f"警告: Ghidra结果文件为空: {file1} 或 {file2}")
            return {
                "file1": file1,
                "file2": file2,
                "total_items1": len(content1),
                "total_items2": len(content2),
                "unique_items1": len(set(content1)),
                "unique_items2": len(set(content2)),
                "common_items": 0,
                "common_items_list": [],
                "similarity": 0.0,
                "weight": weight,
                "weighted_similarity": 0.0
            }
        
        # 转换为集合
        set1 = set(content1)
        set2 = set(content2)
        
        # 计算交集和并集
        intersection = set1.intersection(set2)
        union = set1.union(set2)
        
        # 计算Jaccard相似度
        similarity = len(intersection) / len(union) if union else 0.0
        weighted_similarity = similarity * weight
        
        # 生成结果字典，包含相同对象列表
        result = {
            "file1": file1,
            "file2": file2,
            "total_items1": len(content1),
            "total_items2": len(content2),
            "unique_items1": len(set1),
            "unique_items2": len(set2),
            "common_items": len(intersection),
            "common_items_list": list(intersection),
            "similarity": similarity,
            "weight": weight,
            "weighted_similarity": weighted_similarity
        }
        
        return result
    
    def _read_txt_file(self, file_path):
        """
        读取文本文件，返回非空行列表
        
        Args:
            file_path: 文件路径
            
        Returns:
            list: 非空行列表
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