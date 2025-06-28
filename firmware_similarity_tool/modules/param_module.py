import os
import json
from tqdm import tqdm
from modules.base_module import BaseComparisonModule
from collections import defaultdict

class ParamModule(BaseComparisonModule):
    """
    实现基于参数调用链的固件相似度比较
    """
    
    def __init__(self, config):
        super().__init__(config)
    
    def calculate_similarity(self, firmware1_path, firmware2_path):
        """
        计算基于参数调用链的相似度
        
        Args:
            firmware1_path: 第一个固件特征路径
            firmware2_path: 第二个固件特征路径
            
        Returns:
            tuple: (相似度值, 详细比较结果字典)
        """
        # 获取参数调用链文件路径
        param_link_file1 = self.get_file_path(
            firmware1_path, 
            self.module_config.get('param_link_file1', 'output_json/{firmware_name}/param_link.json')
        )
        
        param_link_file2 = self.get_file_path(
            firmware2_path, 
            self.module_config.get('param_link_file2', 'output_json/{firmware_name}/param_link.json')
        )
        
        # 检查文件是否存在
        if not os.path.exists(param_link_file1):
            raise FileNotFoundError(f"参数调用链文件不存在: {param_link_file1}")
        if not os.path.exists(param_link_file2):
            raise FileNotFoundError(f"参数调用链文件不存在: {param_link_file2}")
        
        # 加载参数调用链数据
        print("正在加载参数调用链数据...")
        param_links1 = self._load_json(param_link_file1)
        param_links2 = self._load_json(param_link_file2)
        
        # 计算相似度（使用保留地址的方法和编辑距离）
        similarity, details = self._calculate_edit_distance_similarity(param_links1, param_links2)
        
        # 添加文件路径到详细结果
        details["param_link_file1"] = param_link_file1
        details["param_link_file2"] = param_link_file2
        
        return similarity, details
    
    def _load_json(self, file_path):
        """加载JSON文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"无法解析JSON文件 {file_path}: {str(e)}")
    
    def _calculate_edit_distance_similarity(self, param_links1, param_links2):
        """
        使用编辑距离计算参数调用链的相似度，保留地址信息（用空格替代）
        
        Args:
            param_links1: 第一个参数调用链数据
            param_links2: 第二个参数调用链数据
            
        Returns:
            tuple: (相似度值, 详细信息字典)
        """
        # 按应用程序和参数名分组
        print("正在按应用程序和参数名分组...")
        grouped_links1 = self._group_param_links(param_links1)
        grouped_links2 = self._group_param_links(param_links2)
        
        # 所有应用程序和参数的组合
        all_apps_params = set(grouped_links1.keys()) | set(grouped_links2.keys())
        
        total_similarity = 0.0
        param_similarities = {}
        matching_details = []
        total_pairs = 0
        
        # 获取每种长度的最大比较链数
        max_links_per_length = self.module_config.get('max_links_per_length', 5)
        
        print(f"正在计算参数调用链相似度，共 {len(all_apps_params)} 个应用参数组合...")
        # 添加进度条
        for app_param in tqdm(all_apps_params, desc="处理应用参数"):
            app_name, param_name = app_param.split(':')
            
            # 获取该应用程序和参数的所有链
            links1 = grouped_links1.get(app_param, [])
            links2 = grouped_links2.get(app_param, [])
            
            if not links1 or not links2:
                # 如果其中一个固件没有该应用参数组合，相似度为0
                param_similarities[app_param] = {
                    "similarity": 0.0,
                    "count1": len(links1),
                    "count2": len(links2)
                }
                continue
            
            # 按链长度分组
            links1_by_length = self._group_links_by_length(links1)
            links2_by_length = self._group_links_by_length(links2)
            
            # 获取所有可能的长度
            all_lengths = set(links1_by_length.keys()) | set(links2_by_length.keys())
            
            best_matches = []
            total_comparisons = 0
            
            # 对每种长度的链进行比较
            for length in all_lengths:
                curr_links1 = links1_by_length.get(length, [])
                curr_links2 = links2_by_length.get(length, [])
                
                # 如果当前长度下有链，进行有限比较
                if curr_links1 and curr_links2:
                    # 限制每种长度的链数量
                    limited_links1 = curr_links1[:max_links_per_length]
                    limited_links2 = curr_links2[:max_links_per_length]
                    
                    # 计算这种长度下实际比较的对数
                    comparisons = len(limited_links1) * len(limited_links2)
                    total_comparisons += comparisons
                    
                    with tqdm(total=comparisons, desc=f"比较链对 ({app_param}, 长度={length})", leave=False) as pbar:
                        for link1 in limited_links1:
                            normalized1 = self._preserve_address_structure(link1)
                            
                            for link2 in limited_links2:
                                normalized2 = self._preserve_address_structure(link2)
                                
                                # 计算编辑距离相似度
                                distance = self._levenshtein_distance(normalized1, normalized2)
                                max_len = max(len(normalized1), len(normalized2))
                                similarity = 1.0 - (distance / max_len) if max_len > 0 else 0.0
                                
                                best_matches.append({
                                    "link1": link1,
                                    "link2": link2,
                                    "length": length,
                                    "normalized1": normalized1,
                                    "normalized2": normalized2,
                                    "distance": distance, 
                                    "similarity": similarity
                                })
                                pbar.update(1)
            
            # 按相似度降序排序
            best_matches.sort(key=lambda x: x["similarity"], reverse=True)
            
            # 计算该应用参数组合的平均相似度
            avg_similarity = sum(match["similarity"] for match in best_matches) / len(best_matches) if best_matches else 0.0
            
            param_similarities[app_param] = {
                "similarity": avg_similarity,
                "count1": len(links1),
                "count2": len(links2),
                "total_comparisons": total_comparisons,
                "best_match": best_matches[0] if best_matches else None
            }
            
            # 添加到总体相似度计算
            weight = max(len(links1), len(links2))
            total_similarity += avg_similarity * weight
            total_pairs += weight
            
            # 记录最佳匹配详情（最多100个）
            if len(matching_details) < 100:
                matching_details.append({
                    "app_name": app_name,
                    "param_name": param_name,
                    "similarity": avg_similarity,
                    "best_match": best_matches[0] if best_matches else None
                })
        
        # 计算加权平均相似度
        overall_similarity = total_similarity / total_pairs if total_pairs > 0 else 0.0
        
        # 准备详细结果
        details = {
            "similarity": overall_similarity,
            "param_similarities": param_similarities,
            "matching_details": matching_details,
            "total_app_params": len(all_apps_params),
            "common_app_params": len(set(grouped_links1.keys()) & set(grouped_links2.keys())),
            "unique_app_params1": len(set(grouped_links1.keys()) - set(grouped_links2.keys())),
            "unique_app_params2": len(set(grouped_links2.keys()) - set(grouped_links1.keys()))
        }
        
        return overall_similarity, details
    
    def _group_param_links(self, param_links):
        """
        按应用程序和参数名分组调用链，参数名统一转换为小写
        
        Args:
            param_links: 参数调用链数据
            
        Returns:
            dict: 分组后的调用链，键为"应用名:参数名"（参数名已转为小写）
        """
        result = {}
        
        # 添加进度条
        for app_name, links in tqdm(param_links.items(), desc="分组应用参数"):
            for link in links:
                try:
                    # 提取参数名并转换为小写
                    param_name = link.split('Param "')[1].split('"')[0] if 'Param "' in link else "unknown"
                    param_name = param_name.lower()  # 转换为小写
                    
                    key = f"{app_name}:{param_name}"
                    
                    if key not in result:
                        result[key] = []
                    result[key].append(link)
                except Exception as e:
                    print(f"参数链分组时出错: {str(e)}, 链: {link}")
                    # 遇到错误继续处理其他链
                    continue
        
        return result
    
    def _group_links_by_length(self, links):
        """
        按链的长度对调用链进行分组
        
        Args:
            links: 调用链列表
            
        Returns:
            dict: 按长度分组的调用链，键为长度，值为该长度的链列表
        """
        result = defaultdict(list)
        for link in links:
            # 计算链的长度（以'->'和'>>'的数量作为衡量标准）
            length = link.count('->') + link.count('>>')
            # 将链添加到对应长度的组中
            result[length].append(link)
        
        # 对每个长度组内的链进行排序（可选，按链的复杂度或其他标准）
        for length, length_links in result.items():
            # 此处可以添加自定义排序逻辑，例如按链的某些特征排序
            # 默认保持原顺序
            pass
            
        return result
    
    def _preserve_address_structure(self, link):
        """
        保留调用链的结构，但将地址部分替换为空格
        
        Args:
            link: 调用链字符串
            
        Returns:
            str: 保留结构的调用链
        """
        try:
            # 替换所有0x开头的地址和FUN_格式的函数名
            parts = []
            
            # 按'->'或'>>'分割
            segments = []
            for part in link.split(' -> '):
                # 处理'>>'分隔的部分
                if '>>' in part:
                    for subpart in part.split('>>'):
                        segments.append(subpart.strip())
                else:
                    segments.append(part.strip())
            
            # 替换地址信息为空格，但保留结构
            for segment in segments:
                # 处理以0x开头的地址
                if segment.startswith('0x'):
                    parts.append(' ' * len(segment))  # 用相同长度的空格替换
                
                # 处理FUN_格式的函数
                elif 'FUN_00' in segment:
                    words = segment.split()
                    replaced_words = []
                    
                    for word in words:
                        if 'FUN_00' in word:
                            replaced_words.append(' ' * len(word))
                        else:
                            replaced_words.append(word)
                    
                    parts.append(' '.join(replaced_words))
                
                # 保留其他部分
                else:
                    parts.append(segment)
            
            # 重建调用链，保持原始分隔符
            result = []
            i = 0
            for part in link.split(' -> '):
                if '>>' in part:
                    subparts = []
                    for _ in part.split('>>'):
                        subparts.append(parts[i])
                        i += 1
                    result.append('>>'.join(subparts))
                else:
                    result.append(parts[i])
                    i += 1
            
            return ' -> '.join(result)
        
        except Exception as e:
            print(f"保留结构时出错: {str(e)}, 链: {link}")
            return link
    
    def _levenshtein_distance(self, s1, s2):
        """
        计算两个字符串之间的编辑距离（Levenshtein距离）
        
        Args:
            s1: 第一个字符串
            s2: 第二个字符串
            
        Returns:
            int: 编辑距离值
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # 计算插入、删除和替换的代价
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                
                # 选择最小代价
                current_row.append(min(insertions, deletions, substitutions))
            
            previous_row = current_row
        
        return previous_row[-1]
    
    def _normalize_param_links(self, param_links):
        """
        将参数调用链标准化，提取函数名序列，忽略地址
        
        Args:
            param_links: 参数调用链数据
            
        Returns:
            dict: 标准化后的调用链字典，键为函数名序列，值为原始调用链列表
        """
        result = {}
        
        # 遍历所有二进制程序的参数调用链
        for app_name, links in param_links.items():
            for link in links:
                # 提取函数调用序列
                normalized = self._extract_function_sequence(link, app_name)
                
                # 将标准化后的调用链作为键，原始链作为值
                if normalized not in result:
                    result[normalized] = []
                result[normalized].append(link)
        
        return result
    
    def _extract_function_sequence(self, link, app_name):
        """
        从调用链中提取函数名序列，完全去除地址信息
        
        Args:
            link: 调用链字符串
            app_name: 应用程序名称
            
        Returns:
            str: 标准化后的函数名序列
        """
        try:
            # 提取参数名并转换为小写
            param_name = link.split('Param "')[1].split('"')[0] if 'Param "' in link else "unknown"
            param_name = param_name.lower()  # 转换为小写
            
            # 提取所有函数名
            functions = []
            
            # 首先处理所有的'->'分隔符
            parts = link.split(' -> ')
            
            # 处理第一部分，可能包含多个'>>'
            if '>>' in parts[0]:
                # 分割所有的'>>'部分
                segments = parts[0].split('>>')
                
                # 从第一段提取引用位置的函数
                if 'Referenced at ' in segments[0]:
                    func = segments[0].split('Referenced at ')[1].split(' :')[0].strip()
                    # 只添加不以0x开头的函数名且不是FUN_格式
                    if not func.startswith('0x') and not 'FUN_00' in func:
                        functions.append(func)
                
                # 处理剩余的'>>'分隔的段落
                for i in range(1, len(segments)):
                    segment = segments[i].strip()
                    # 如果片段包含空格，提取第一个单词作为函数名
                    if ' ' in segment:
                        segment = segment.split(' ')[0]
                    # 过滤掉0x开头的地址和FUN_格式的函数
                    if not segment.startswith('0x') and not 'FUN_00' in segment:
                        functions.append(segment)
            
            # 处理其他部分，这些部分是由' -> '分隔的
            for i in range(1, len(parts)):
                part = parts[i].strip()
                # 检查是否还有嵌套的'>>'
                if '>>' in part:
                    subparts = part.split('>>')
                    for subpart in subparts:
                        subpart = subpart.strip()
                        if ' ' in subpart:
                            subpart = subpart.split(' ')[0]
                        if not subpart.startswith('0x') and not 'FUN_00' in subpart:
                            functions.append(subpart)
                else:
                    # 处理正常的函数名部分
                    if ' ' in part:
                        part = part.split(' ')[0]
                    if not part.startswith('0x') and not 'FUN_00' in part:
                        functions.append(part)
            
            # 生成标准化字符串，格式：应用名:参数名:函数1,函数2,...
            return f"{app_name}:{param_name}:{','.join(functions)}"
        
        except Exception as e:
            # 如果解析失败，返回原始链
            print(f"解析调用链失败: {str(e)}, 链: {link}")
            return f"{app_name}:error:{link}"
