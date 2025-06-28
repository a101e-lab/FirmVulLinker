# 模块包初始化文件

# 可用的模块列表
from modules.base_module import BaseComparisonModule
from modules.binwalk_module import BinwalkModule
from modules.interface_exposure_profile_module import InterfaceExposureProfileModule
from modules.param_module import ParamModule
from modules.ghidra_module import GhidraModule
from modules.filesystem_profile_module import FileSystemProfileModule

# 所有可用模块的列表
AVAILABLE_MODULES = [
    BinwalkModule,
    InterfaceExposureProfileModule,
    ParamModule,
    GhidraModule,
    FileSystemProfileModule
] 