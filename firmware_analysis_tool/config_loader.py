import os
import yaml

def load_config(config_file="config.yaml"):
    """加载配置文件"""
    # 获取脚本所在目录
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, config_file)
    
    # 检查配置文件是否存在
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"配置文件 {config_path} 不存在")
    
    # 读取配置文件
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    # 处理相对路径，使其变为绝对路径
    for section in ["directories", "satc"]:
        if section in config:
            for key, value in config[section].items():
                if isinstance(value, str) and not os.path.isabs(value):
                    config[section][key] = os.path.join(base_dir, value)
    
    # 特殊处理 Ghidra 路径
    if "tool" in config and "ghidra" in config["tool"]:
        ghidra_path = config["tool"]["ghidra"]["path"]
        if not os.path.isabs(ghidra_path):
            config["tool"]["ghidra"]["path"] = os.path.join(base_dir, ghidra_path)
        
        headless_script = config["tool"]["ghidra"]["headless_script"]
        config["tool"]["ghidra"]["headless_full_path"] = os.path.join(
            config["tool"]["ghidra"]["path"], 
            headless_script
        )
        
        script_path = config["tool"]["ghidra"]["script_path"]
        if not os.path.isabs(script_path):
            config["tool"]["ghidra"]["script_path"] = os.path.join(base_dir, script_path)
    
    return config 