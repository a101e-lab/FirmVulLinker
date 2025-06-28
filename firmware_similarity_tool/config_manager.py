import os
import yaml

class ConfigManager:
    def __init__(self, config_path):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self):
        """加载配置文件"""
        if not os.path.exists(self.config_path):
            print(f"配置文件不存在: {self.config_path}")
            raise FileNotFoundError(f"配置文件不存在: {self.config_path}")
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def get_module_weight(self, module_name):
        """获取模块权重"""
        module_name = self._normalize_module_name(module_name)
        return self.config.get('module_weights', {}).get(module_name, 1.0)
    
    def is_module_enabled(self, module_name):
        """检查模块是否启用"""
        module_name = self._normalize_module_name(module_name)
        return self.config.get('modules', {}).get(module_name, False)
    
    def get_module_config(self, module_name):
        """获取模块特定配置"""
        module_name = self._normalize_module_name(module_name)
        return self.config.get('module_configs', {}).get(module_name, {})
    
    def get_result_dir(self):
        """获取结果目录"""
        return self.config.get('result_dir', 'comparison_results')
    
    def get_logging_config(self):
        """获取日志配置"""
        return self.config.get('logging', {})
    
    def get_enabled_modules(self):
        """获取所有启用的模块列表"""
        enabled_modules = []
        modules_config = self.config.get('modules', {})
        for module_name, is_enabled in modules_config.items():
            if is_enabled:
                enabled_modules.append(module_name)
        return enabled_modules
    
    def update_enabled_modules(self, module_list):
        """更新启用的模块列表"""
        # 首先禁用所有模块
        for module_name in self.config.get('modules', {}):
            self.config['modules'][module_name] = False
        
        # 启用指定的模块
        for module_name in module_list:
            norm_name = self._normalize_module_name(module_name)
            if norm_name in self.config.get('modules', {}):
                self.config['modules'][norm_name] = True
            else:
                print(f"警告: 未知模块 '{module_name}'")
    
    def _normalize_module_name(self, module_name):
        """标准化模块名称，移除'Module'后缀"""
        if module_name.endswith('Module'):
            return module_name[:-6].lower()
        return module_name.lower()
    
    def save_config(self, path=None):
        """保存配置到文件"""
        save_path = path or self.config_path
        with open(save_path, 'w', encoding='utf-8') as f:
            yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True) 