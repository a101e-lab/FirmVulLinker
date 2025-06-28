def calculate_combined_similarity(set1, set2):
    """
    结合多种相似度计算算法，返回加权平均值
    
    Args:
        set1: 第一个集合
        set2: 第二个集合
        
    Returns:
        float: 综合相似度值
    """
    # 处理空集情况
    if not set1 and not set2:
        return 0.0
    if not set1 or not set2:
        return 0.0
    
    # 计算交集和并集
    intersection = set1.intersection(set2)
    union = set1.union(set2)
    
    # 1. Jaccard系数 (交集/并集)
    jaccard = len(intersection) / len(union) if union else 0.0
    
    # 2. Dice系数 (2*交集/(A+B))
    dice = 2 * len(intersection) / (len(set1) + len(set2))
    
    # 3. Overlap系数 (交集/min(A,B))
    overlap = len(intersection) / min(len(set1), len(set2))
    
    # 4. Cosine相似度 (交集/sqrt(A*B))
    cosine = len(intersection) / (len(set1) * len(set2))**0.5 if len(set1) > 0 and len(set2) > 0 else 0.0
    
    # 5. F1分数 (2*精确率*召回率/(精确率+召回率))
    precision = len(intersection) / len(set1)
    recall = len(intersection) / len(set2)
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    # 定义各算法权重
    weights = {
        "jaccard": 0.3,   
        "dice": 0.2,      
        "overlap": 0.1,   
        "cosine": 0.2,    
        "f1": 0.2         
    }
    
    combined = (
        jaccard * weights["jaccard"] +
        dice * weights["dice"] +
        overlap * weights["overlap"] +
        cosine * weights["cosine"] +
        f1 * weights["f1"]
    )
    
    return combined