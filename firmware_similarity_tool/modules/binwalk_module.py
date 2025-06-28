import os
import json
import numpy as np
from collections import Counter
from modules.base_module import BaseComparisonModule
from modules.similarity_utils import calculate_combined_similarity

# TODO:需要修改binwalk计算的算法，参考论文初稿，添加频率的余弦相似度的计算方法，使binwalk的影响由负影响到正影响

class BinwalkModule(BaseComparisonModule):
    """
    实现基于binwalk结果的固件相似度比较
    使用解包签名序列画像相似度（Unpacking Signature Sequence Similarity）算法
    """
    
    def __init__(self, config):
        super().__init__(config)
    
    def calculate_similarity(self, firmware1_path, firmware2_path):
        """
        计算基于binwalk结果的相似度
        
        Args:
            firmware1_path: 第一个固件特征路径
            firmware2_path: 第二个固件特征路径
            
        Returns:
            tuple: (相似度值, 详细比较结果字典)
        """
        # 获取binwalk结果文件路径
        binwalk_file1 = self.get_file_path(
            firmware1_path, 
            self.module_config.get('binwalk_file1', 'binwalk_docker_result/binwalk_log/{firmware_dir}.json')
        )
        
        binwalk_file2 = self.get_file_path(
            firmware2_path, 
            self.module_config.get('binwalk_file2', 'binwalk_docker_result/binwalk_log/{firmware_dir}.json')
        )
        
        # 检查文件是否存在
        if not os.path.exists(binwalk_file1):
            raise FileNotFoundError(f"Binwalk结果文件不存在: {binwalk_file1}")
        if not os.path.exists(binwalk_file2):
            raise FileNotFoundError(f"Binwalk结果文件不存在: {binwalk_file2}")
        
        # 加载binwalk结果
        binwalk_data1 = self._load_json(binwalk_file1)
        binwalk_data2 = self._load_json(binwalk_file2)
        
        # 提取VECTOR数据（结构签名序列 S(F)）
        vector1 = self._extract_vector(binwalk_data1)
        vector2 = self._extract_vector(binwalk_data2)
        
        # 将向量展平为序列
        seq1 = self._flatten_vector(vector1)
        seq2 = self._flatten_vector(vector2)
        total_ngrams_1 = set()
        total_ngrams_2 = set()
        # 获取n-gram大小
        n = self.module_config.get('ngram_size')
        for single_n in n:
            single_ngrams_1 = set(self._generate_ngrams(seq1, single_n))
            single_ngrams_2 = set(self._generate_ngrams(seq2, single_n))
            total_ngrams_1.update(single_ngrams_1)
            total_ngrams_2.update(single_ngrams_2)
        
        
        ngrams1 = total_ngrams_1
        ngrams2 = total_ngrams_2
        
        # # 生成n-gram模式集合 G_k(F1) 和 G_k(F2)
        # ngrams1 = set(self._generate_ngrams(seq1, n))
        # ngrams2 = set(self._generate_ngrams(seq2, n))
        
        # 如果序列过短无法生成n-gram，回退到基于特征的方法
        if len(ngrams1) == 0 or len(ngrams2) == 0:
            features1 = self._extract_binwalk_features(binwalk_data1)
            features2 = self._extract_binwalk_features(binwalk_data2)
            similarity = self._calculate_feature_similarity(features1, features2)
            
            details = {
                "binwalk_file1": binwalk_file1,
                "binwalk_file2": binwalk_file2,
                "method": "fallback_feature_similarity",
                "similarity": similarity,
                "vector1_length": len(seq1),
                "vector2_length": len(seq2)
            }
            
            return similarity, details
        
        # 1. 计算集合层的Jaccard相似系数 Sim_sig^set(F1, F2)
        set_similarity = self._calculate_jaccard_similarity(ngrams1, ngrams2)
        
        # 2. 计算频率向量的余弦相似度 Sim_sig^vec(F1, F2)
        freq_similarity = self._calculate_frequency_similarity(ngrams1, ngrams2, seq1, seq2, n)
        
        # 3. 综合相似度（等权融合）
        combined_similarity = (set_similarity + freq_similarity) / 2.0
        
        # 准备详细结果
        common_ngrams = list(ngrams1.intersection(ngrams2))
        details = {
            "binwalk_file1": binwalk_file1,
            "binwalk_file2": binwalk_file2,
            "ngram_size": n,
            "set_similarity": set_similarity,
            "frequency_similarity": freq_similarity,
            "combined_similarity": combined_similarity,
            "vector1_length": len(seq1),
            "vector2_length": len(seq2),
            "ngrams1_count": len(ngrams1),
            "ngrams2_count": len(ngrams2),
            "common_ngrams_count": len(common_ngrams),
            "common_ngrams_sample": str(list(common_ngrams)[:10]) if len(common_ngrams) > 10 else str(list(common_ngrams))
        }
        
        return combined_similarity, details
    
    def _load_json(self, file_path):
        """加载JSON文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"无法解析JSON文件 {file_path}: {str(e)}")
    
    def _extract_vector(self, binwalk_data):
        """
        从binwalk结果提取VECTOR数据（结构签名序列）
        
        Args:
            binwalk_data: binwalk结果数据
            
        Returns:
            list: VECTOR列表
        """
        # 首先尝试直接获取VECTOR字段
        if isinstance(binwalk_data, dict) and "VECTOR" in binwalk_data:
            return binwalk_data["VECTOR"]
        
        # 如果没有VECTOR字段，从结构中提取特征构建向量
        vector = []
        if isinstance(binwalk_data, dict):
            # 按照偏移量排序
            sorted_offsets = sorted([int(offset) for offset in binwalk_data.keys() if offset.isdigit()])
            for offset in sorted_offsets:
                offset_str = str(offset)
                info = binwalk_data.get(offset_str, {})
                if isinstance(info, dict):
                    description = info.get('description', '')
                    if description:
                        # 提取描述中的关键信息
                        parts = description.split(',')
                        for part in parts:
                            vector.append(part.strip())
        elif isinstance(binwalk_data, list):
            # 如果是列表形式
            for item in binwalk_data:
                if isinstance(item, dict):
                    description = item.get('description', '')
                    if description:
                        parts = description.split(',')
                        for part in parts:
                            vector.append(part.strip())
        
        return [vector]  # 返回嵌套列表，与VECTOR字段格式一致
    
    def _flatten_vector(self, vector):
        """
        将嵌套的VECTOR列表展平为单个序列
        
        Args:
            vector: VECTOR列表
            
        Returns:
            list: 展平后的序列
        """
        if not vector:
            return []
        
        # 展平嵌套列表
        return [item for sublist in vector for item in sublist]
    
    def _generate_ngrams(self, sequence, n):
        """
        生成序列的n-gram（结构n-gram模式）
        
        Args:
            sequence: 输入序列
            n: n-gram的长度
            
        Returns:
            list: n-gram列表
        """
        if len(sequence) < n:
            return []
        
        return [tuple(sequence[i:i+n]) for i in range(len(sequence) - n + 1)]
    
    def _calculate_jaccard_similarity(self, set1, set2):
        """
        计算两个集合的Jaccard相似系数
        
        Args:
            set1: 第一个集合
            set2: 第二个集合
            
        Returns:
            float: Jaccard相似系数
        """
        if not set1 or not set2:
            return 0.0
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        if union == 0:
            return 0.0
            
        return intersection / union
    
    def _calculate_frequency_similarity(self, ngrams1, ngrams2, seq1, seq2, n_list):
        """
        计算两个序列在n-gram模式上的频率相似度（余弦相似度）
        
        Args:
            ngrams1: 第一个序列的n-gram集合
            ngrams2: 第二个序列的n-gram集合
            seq1: 第一个完整序列
            seq2: 第二个完整序列
            n_list: 一个包含要考虑的n-gram长度的列表 (例如 [3, 4, 5])
            
        Returns:
            float: 频率向量的余弦相似度
        """
        if not ngrams1 or not ngrams2:
            return 0.0
        
        # 创建全局统一词表
        global_vocab = list(ngrams1.union(ngrams2))
        vocab_size = len(global_vocab)
        
        if vocab_size == 0:
            return 0.0
        
        # 为了方便索引，创建映射字典
        vocab_map = {gram: idx for idx, gram in enumerate(global_vocab)}
        
        

        # 计算n-gram在各自序列中的频率
        all_ngrams_from_seq1 = []
        for n_val in n_list:
            all_ngrams_from_seq1.extend(self._generate_ngrams(seq1, n_val))
        
        all_ngrams_from_seq2 = []
        for n_val in n_list:
            all_ngrams_from_seq2.extend(self._generate_ngrams(seq2, n_val))

        # 统计频率
        counter1 = Counter(all_ngrams_from_seq1)
        counter2 = Counter(all_ngrams_from_seq2)
        
        # 构建频率向量
        freq_vector1 = np.zeros(vocab_size, dtype=float)
        freq_vector2 = np.zeros(vocab_size, dtype=float)
        
        for gram, idx in vocab_map.items():
            freq_vector1[idx] = counter1.get(gram, 0)
            freq_vector2[idx] = counter2.get(gram, 0)
        
        # 计算余弦相似度
        norm1 = np.linalg.norm(freq_vector1)
        norm2 = np.linalg.norm(freq_vector2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
            
        cosine_sim = np.dot(freq_vector1, freq_vector2) / (norm1 * norm2)
        
        return cosine_sim
    
    def _extract_binwalk_features(self, binwalk_data):
        """
        从binwalk结果提取特征（用于回退方法）
        
        Args:
            binwalk_data: binwalk结果数据
            
        Returns:
            list: 特征列表
        """
        features = []
        
        if isinstance(binwalk_data, dict):
            for offset, info in binwalk_data.items():
                if isinstance(info, dict):
                    description = info.get('description', '')
                    if description:
                        features.append(f"{offset}:{description}")
        elif isinstance(binwalk_data, list):
            for item in binwalk_data:
                if isinstance(item, dict):
                    offset = item.get('offset', '')
                    description = item.get('description', '')
                    if offset and description:
                        features.append(f"{offset}:{description}")
        
        return features
    
    def _calculate_feature_similarity(self, features1, features2):
        """计算特征列表的相似度（用于回退方法）"""
        if not features1 or not features2:
            return 0.0
        
        set1 = set(features1)
        set2 = set(features2)
        
        # 计算Jaccard相似度作为回退方法
        return self._calculate_jaccard_similarity(set1, set2) 