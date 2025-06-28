import os
import importlib
import inspect
import sys

class BaseComparisonModule:
    """比较模块基类，定义所有比较模块的通用接口"""
    
    def __init__(self, config):
        """
        初始化比较模块
        
        Args:
            config: 配置管理器实例
        """
        self.config = config
        # 使用类名作为模块名（移除'Module'后缀）
        if self.__class__.__name__.endswith('Module'):
            self.name = self.__class__.__name__[:-6].lower()
        else:
            self.name = self.__class__.__name__.lower()
        
        self.weight = config.get_module_weight(self.name)
        self.enabled = config.is_module_enabled(self.name)
        self.module_config = config.get_module_config(self.name)
    
    def calculate_similarity(self, firmware1_path, firmware2_path):
        """
        计算两个固件的相似度
        
        Args:
            firmware1_path: 第一个固件特征路径
            firmware2_path: 第二个固件特征路径
            
        Returns:
            tuple: (相似度值, 详细比较结果字典)
        """
        raise NotImplementedError("子类必须实现calculate_similarity方法")
    
    def get_file_path(self, firmware_path, file_template):
        """
        根据模板字符串获取文件路径
        
        Args:
            firmware_path: 固件路径
            file_template: 文件路径模板
            
        Returns:
            str: 完整文件路径
        """
        if not file_template:
            return None
        
        # 获取固件名和固件目录
        firmware_name = os.path.basename(firmware_path)
        firmware_dir = ""
        
        # 通过比较当前模块正在处理的路径来确定是固件1还是固件2
        if 'FIRMWARE1_PATH' in os.environ and firmware_path == os.environ.get('FIRMWARE1_PATH'):
            # 这是固件1
            firmware_dir = os.environ.get('FIRMWARE1_DIR', '')
        elif 'FIRMWARE2_PATH' in os.environ and firmware_path == os.environ.get('FIRMWARE2_PATH'):
            # 这是固件2
            firmware_dir = os.environ.get('FIRMWARE2_DIR', '')
        
        # 如果环境变量中没有设置固件目录，则尝试检测实际固件目录
        if not firmware_dir:
            firmware_dir = self._find_actual_firmware_dir(firmware_path)
        
        # 替换模板中的占位符
        file_path = file_template.format(
            firmware_name=firmware_name,
            firmware_dir=firmware_dir
        )
        
        # 如果路径是相对路径，则相对于firmware_path解析
        if not os.path.isabs(file_path):
            file_path = os.path.join(firmware_path, file_path)
        
        return file_path
    
    def _find_actual_firmware_dir(self, firmware_path):
        """
        找到固件路径下的实际固件目录名
        
        Args:
            firmware_path: 固件顶级路径
            
        Returns:
            str: 实际固件目录名
        """
        # 检查output_json目录
        output_json_dir = os.path.join(firmware_path, "output_json")
        if os.path.exists(output_json_dir):
            subdirs = [d for d in os.listdir(output_json_dir) 
                       if os.path.isdir(os.path.join(output_json_dir, d))]
            if subdirs:
                return subdirs[0]  # 返回第一个子目录名称
        
        # 如果找不到实际目录，返回固件顶级目录名
        return os.path.basename(firmware_path)

def load_all_modules(config_manager):
    """
    加载所有启用的比较模块
    
    Args:
        config_manager: 配置管理器实例
        
    Returns:
        list: 已初始化的比较模块实例列表
    """
    # 导入所有模块类
    from modules import AVAILABLE_MODULES
    
    # 初始化启用的模块
    enabled_modules = []
    for module_class in AVAILABLE_MODULES:
        module = module_class(config_manager)
        if module.enabled:
            enabled_modules.append(module)
    
    return enabled_modules 