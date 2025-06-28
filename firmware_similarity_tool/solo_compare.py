import pandas as pd
import numpy as np

def calculate_total_similarity(row, weights):
    """
    根据各模块相似度和权重计算总相似度
    
    Args:
        row: 包含各模块相似度的数据行
        weights: 各模块的权重字典
    
    Returns:
        float: 计算的总体相似度值
    """
    # 初始化总权重和加权相似度和
    total_weight = 0.0
    weighted_similarity_sum = 0.0
    
    # 遍历每个模块
    for module_name, weight in weights.items():
        # 获取模块相似度
        module_similarity = row[module_name]
        
        # 累加加权相似度和总权重
        weighted_similarity_sum += module_similarity * weight
        total_weight += weight
    
    # 计算加权平均相似度
    if total_weight > 0:
        return weighted_similarity_sum / total_weight
    else:
        return 0.0

def calculate_metrics(df, threshold, weights):
    # 先计算total_similarity
    df['calculated_total_similarity'] = df.apply(
        lambda row: calculate_total_similarity(row, weights), axis=1
    )
    
    # 定义需要分析的相似度列
    # similarity_columns = ['calculated_total_similarity', 'binwalk', 'interface_exposure', 'param', 'ghidra', 'filesystem_profile']
    similarity_columns = ['calculated_total_similarity'] 
    # 存储结果
    results = {}
    
    # 遍历每一列进行分析
    for column in similarity_columns:
        # 计数大于和小于阈值的数量
        above_threshold = sum(df[column] >= threshold)
        below_threshold = sum(df[column] < threshold)
        
        # 根据阈值预测相似度判断
        df[f'{column}_pred'] = df[column].apply(lambda x: '是' if x >= threshold else '否')
        
        # 计算混淆矩阵
        true_positive = sum((df['基准判断情况'] == '是') & (df[f'{column}_pred'] == '是'))
        true_negative = sum((df['基准判断情况'] == '否') & (df[f'{column}_pred'] == '否'))
        false_positive = sum((df['基准判断情况'] == '否') & (df[f'{column}_pred'] == '是'))
        false_negative = sum((df['基准判断情况'] == '是') & (df[f'{column}_pred'] == '否'))
        
        # 计算评估指标
        precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) > 0 else 0
        recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) > 0 else 0
        false_positive_rate = false_positive / (false_positive + true_negative) if (false_positive + true_negative) > 0 else 0
        false_negative_rate = false_negative / (false_negative + true_positive) if (false_negative + true_positive) > 0 else 0
        
        # 存储该列的统计结果
        results[column] = {
            '大于阈值数量': above_threshold,
            '小于阈值数量': below_threshold,
            '真正例(TP)': true_positive,
            '真负例(TN)': true_negative,
            '假正例(FP)': false_positive,
            '假负例(FN)': false_negative,
            '精确率': precision,
            '召回率': recall,
            '误报率': false_positive_rate,
            '漏报率': false_negative_rate
        }
    
    return results

def analyze_threshold(csv_file, threshold, weights=None):
    # 读取CSV文件
    df = pd.read_csv(csv_file)
    
    # 如果未提供权重，使用默认权重
    if weights is None:
        weights = {
            'binwalk': 0.1,             # 二进制结构相似度
            'interface_exposure': 0.3,   # 通信接口暴露画像相似度
            'param': 0.3,               # 参数调用链相似度
            'ghidra': 0.1,              # Ghidra函数相似度
            'filesystem_profile': 0.2    # 文件系统语义画像相似度
        }
    
    # 分析数据
    results = calculate_metrics(df, threshold, weights)
    
    # 打印结果
    print(f"阈值设置为: {threshold}\n")
    print(f"使用的权重: {weights}\n")
    
    for column, metrics in results.items():
        # 如果是计算出的total_similarity，修改显示名称
        display_name = "总相似度(计算值)" if column == "calculated_total_similarity" else column
        
        print(f"【{display_name}】列分析:")
        print(f"  大于阈值数量: {metrics['大于阈值数量']}")
        print(f"  小于阈值数量: {metrics['小于阈值数量']}")
        print(f"  真正例(TP): {metrics['真正例(TP)']}")
        print(f"  真负例(TN): {metrics['真负例(TN)']}")
        print(f"  假正例(FP): {metrics['假正例(FP)']}")
        print(f"  假负例(FN): {metrics['假负例(FN)']}")
        print(f"  精确率: {metrics['精确率']:.4f}")
        print(f"  召回率: {metrics['召回率']:.4f}")
        print(f"  误报率: {metrics['误报率']:.4f}")
        print(f"  漏报率: {metrics['漏报率']:.4f}")
        print()

def load_weights_from_yaml(yaml_file):
    """
    从YAML配置文件加载权重
    
    Args:
        yaml_file: YAML配置文件路径
    
    Returns:
        dict: 模块权重字典
    """
    try:
        import yaml
        with open(yaml_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return config.get('module_weights', {})
    except Exception as e:
        print(f"加载配置文件失败: {e}")
        return None

if __name__ == "__main__":
    # 获取用户输入
    csv_file = "/home/IOT/Data_processing_code/firmware_similarity_tool_bak/comparison_results_medium_ngram3_after_delete_bm54_test.csv"
    threshold = 0.5
    
    # 询问是否使用配置文件加载权重
    # use_config = input("是否从配置文件加载权重? (y/n): ").lower() == 'y'
    
    weights = None
    # if use_config:
    #     config_file = input("请输入配置文件路径: ")
    #     weights = load_weights_from_yaml(config_file)
    
    # # 如果未从配置文件加载权重，询问用户是否手动输入
    # if weights is None:
    #     manual_input = input("是否手动输入权重? (y/n): ").lower() == 'y'
    #     if manual_input:
    #         weights = {}
    #         print("请输入各模块权重(0-1之间):")
    #         weights['binwalk'] = float(input("binwalk权重: "))
    #         weights['interface_exposure'] = float(input("interface_exposure权重: "))
    #         weights['param'] = float(input("param权重: "))
    #         weights['ghidra'] = float(input("ghidra权重: "))
    #         weights['filesystem_profile'] = float(input("filesystem_profile权重: "))
    
    # 分析数据
    
    
    
    weights = {
            'binwalk': 0.1,             # 二进制结构相似度
            'interface_exposure': 0.3,   # 通信接口暴露画像相似度
            'param': 0.3,               # 参数调用链相似度
            'ghidra': 0.1,              # Ghidra函数相似度
            'filesystem_profile': 0.2    # 文件系统语义画像相似度
        }
    
    analyze_threshold(csv_file, threshold, weights)
    import copy
    
    for single_weight in weights.keys():
        print('-------',single_weight,'-------')
        temp_weights = copy.deepcopy(weights)
        total_weight = 1-weights[single_weight]
        for temp_single_weight in temp_weights.keys():
            if(temp_single_weight == single_weight):
                temp_weights[single_weight] = 0
            else:
                temp_weights[temp_single_weight] = weights[temp_single_weight]/total_weight
        print(temp_weights)
        analyze_threshold(csv_file, threshold, temp_weights)
        
        
        
    # for single_weight in weights.keys():
    #     print('-------',single_weight,'-------')
    #     temp_weights = copy.deepcopy(weights)
    #     total_weight = 1
    #     for temp_single_weight in temp_weights.keys():
    #         if(temp_single_weight != single_weight):
    #             temp_weights[temp_single_weight] = 0
    #     print(temp_weights)
    #     analyze_threshold(csv_file, threshold, temp_weights)