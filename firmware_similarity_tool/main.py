import os
import argparse
import yaml
import json
from datetime import datetime
from config_manager import ConfigManager
from modules.base_module import load_all_modules

def parse_arguments():
    parser = argparse.ArgumentParser(description='固件相似度比较工具')
    parser.add_argument('firmware1', help='第一个固件特征路径')
    parser.add_argument('firmware2', help='第二个固件特征路径')
    parser.add_argument('--firmware1_dir', help='第一个固件内部目录名（如不指定则自动检测）')
    parser.add_argument('--firmware2_dir', help='第二个固件内部目录名（如不指定则自动检测）')
    parser.add_argument('--config', default='config.yaml', help='配置文件路径')
    parser.add_argument('--output_dir', default='comparison_results', help='输出目录路径')
    parser.add_argument('--modules', help='要启用的模块，以逗号分隔（覆盖配置文件设置）')
    parser.add_argument('--similarity-threshold', type=float, help='相似度判断阈值，大于等于该值判定为相似')
    return parser.parse_args()

def ensure_directory(directory):
    """确保目录存在，如果不存在则创建"""
    if not os.path.exists(directory):
        os.makedirs(directory)

def main():
    # 解析命令行参数
    args = parse_arguments()
    
    # 初始化配置管理器
    config_manager = ConfigManager(args.config)
    
    # 如果指定了相似度阈值，则更新配置
    if args.similarity_threshold is not None:
        config_manager.update_similarity_threshold(args.similarity_threshold)
    
    # 如果指定了模块，则更新配置
    if args.modules:
        enabled_modules = args.modules.split(',')
        config_manager.update_enabled_modules(enabled_modules)
    
    # 准备输出目录
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    # 获取两个固件的basename作为目录名的一部分
    firmware1_path = os.path.abspath(args.firmware1)
    firmware2_path = os.path.abspath(args.firmware2)
    firmware1_basename = os.path.basename(firmware1_path)
    firmware2_basename = os.path.basename(firmware2_path)
    output_dir = os.path.join(args.output_dir, f"{firmware1_basename}_{firmware2_basename}_{timestamp}")
    ensure_directory(output_dir)
    
    # 检测固件目录并打印信息
    firmware1_path = os.path.abspath(args.firmware1)
    firmware2_path = os.path.abspath(args.firmware2)
    
    # 设置固件路径环境变量
    os.environ['FIRMWARE1_PATH'] = firmware1_path
    os.environ['FIRMWARE2_PATH'] = firmware2_path
    
    # 如果指定了固件目录名，则更新环境变量
    if args.firmware1_dir:
        os.environ['FIRMWARE1_DIR'] = args.firmware1_dir
    if args.firmware2_dir:
        os.environ['FIRMWARE2_DIR'] = args.firmware2_dir
    
    # 检测每个固件路径下的实际固件目录
    output_json_dir1 = os.path.join(firmware1_path, "output_json")
    output_json_dir2 = os.path.join(firmware2_path, "output_json")
    
    if os.path.exists(output_json_dir1):
        subdirs1 = [d for d in os.listdir(output_json_dir1) 
                   if os.path.isdir(os.path.join(output_json_dir1, d))]
        if subdirs1 :
        # if subdirs1 and not args.firmware1_dir:
            os.environ['FIRMWARE1_DIR'] = subdirs1[0]
            print(f"检测到固件1的实际目录名: {subdirs1[0]}")
    
    if os.path.exists(output_json_dir2):
        subdirs2 = [d for d in os.listdir(output_json_dir2) 
                   if os.path.isdir(os.path.join(output_json_dir2, d))]
        if subdirs2 :
        # if subdirs2 and not args.firmware2_dir:
            os.environ['FIRMWARE2_DIR'] = subdirs2[0]
            print(f"检测到固件2的实际目录名: {subdirs2[0]}")
    
    # 加载所有启用的模块
    modules = load_all_modules(config_manager)
    
    # 记录比较信息
    comparison_info = {
        "firmware1": firmware1_path,
        "firmware2": firmware2_path,
        "firmware1_dir": os.environ.get('FIRMWARE1_DIR', os.path.basename(args.firmware1)),
        "firmware2_dir": os.environ.get('FIRMWARE2_DIR', os.path.basename(args.firmware2)),
        "timestamp": timestamp,
        "modules": [module.name for module in modules],
        "module_results": {}
    }
    
    # 运行每个模块并保存结果
    for module in modules:
        print(f"运行模块: {module.name}")
        try:
            # 计算模块相似度
            similarity, details = module.calculate_similarity(args.firmware1, args.firmware2)
            
            # 为每个模块创建结果目录
            module_result_dir = os.path.join(output_dir, module.name)
            ensure_directory(module_result_dir)
            
            # 保存详细结果
            details_file = os.path.join(module_result_dir, f"{module.name}_details.json")
            with open(details_file, 'w', encoding='utf-8') as f:
                json.dump(details, f, indent=4, ensure_ascii=False)
            
            # 添加到总结果
            comparison_info["module_results"][module.name] = {
                "similarity": similarity,
                "details_file": details_file
            }
            
            print(f"  相似度: {similarity:.4f}")
        except Exception as e:
            print(f"  模块运行失败: {str(e)}")
            comparison_info["module_results"][module.name] = {
                "error": str(e)
            }
    
    # 计算总体相似度
    total_similarity = calculate_total_similarity(comparison_info, config_manager)
    comparison_info["total_similarity"] = total_similarity
    print(f"\n总体相似度: {total_similarity:.4f}")
    
    # 保存总体比较信息
    summary_file = os.path.join(output_dir, "comparison_summary.json")
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(comparison_info, f, indent=4, ensure_ascii=False)
    
    print(f"\n比较完成！结果已保存到: {output_dir}")
    print(f"摘要文件: {summary_file}")

def calculate_total_similarity(comparison_info, config_manager):
    """
    计算总体相似度
    
    Args:
        comparison_info: 包含各模块相似度结果的字典
        config_manager: 配置管理器实例
    
    Returns:
        float: 总体相似度值
    """
    # 初始化总权重和加权相似度和
    total_weight = 0.0
    weighted_similarity_sum = 0.0
    
    # 获取所有启用的模块名称
    enabled_modules = config_manager.get_enabled_modules()
    
    # 遍历所有启用的模块
    for module_name in enabled_modules:
        # 获取模块权重
        module_weight = config_manager.get_module_weight(module_name)
        
        # 获取模块相似度
        if module_name in comparison_info["module_results"]:
            result = comparison_info["module_results"][module_name]
            if "error" in result:
                # 如果模块出错，相似度设为0
                module_similarity = 0.0
            else:
                module_similarity = result["similarity"]
        else:
            # 如果模块结果不存在，相似度设为0
            module_similarity = 0.0
        
        # 累加加权相似度和总权重
        weighted_similarity_sum += module_similarity * module_weight
        total_weight += module_weight
    
    # 计算加权平均相似度
    if total_weight > 0:
        return weighted_similarity_sum / total_weight
    else:
        return 0.0

if __name__ == "__main__":
    main() 