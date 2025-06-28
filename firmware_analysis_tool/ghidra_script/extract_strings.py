# -*- coding: utf-8 -*-

# 导入 Ghidra 必要的类
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.symbol import SymbolTable, SymbolType
import json
from collections import OrderedDict
# from ghidra.program.model.listing import Program

def extract_common_info():
    program = currentProgram
    # 获取程序基本信息
    program_name = program.getDomainFile().getName()
    entry_point = program.getImageBase()
    # 使用 getAddressOfEntryPoint() 方法获取入口地址
    # entry_point_address = ghidra.app.util.bin.format.pe.getAddressOfEntryPoint()
    # entry_point_address = program.getEntryPoint()

    common_info = OrderedDict()
    common_info["program_name"] = program_name
    common_info["entry_point"] = str(entry_point)
    common_info["functions"] = []

    # 获取所有函数的信息
    func_manager = program.getFunctionManager()
    functions = func_manager.getFunctions(False)  # True 表示获取所有函数，包括外部的
    for func in functions:
        if not func.isExternal():
            func_info = {
                "func_name": func.getName(),
                "func_signature": str(func.getSignature())
            }
        common_info["functions"].append(func_info)
    return common_info
def get_imports():
    sm = currentProgram.getSymbolTable()
    symb = sm.getExternalSymbols()
    
    imports_list = []
    for s in symb:
        imports_list.append(str(s))
    
    return imports_list

def get_exports():
        
    # Get the symbol table of the current program
    symtab = currentProgram.getSymbolTable()

    # Get all external entry points.
    # This is an iterator of addresses for exports.
    exportAddrs = symtab.getExternalEntryPointIterator()
    exports_list = []
    # Iterate the entry point addresses to get the relative symbol.
    # Print the symbol name if successfully got.
    for addr in exportAddrs:
        sym = symtab.getPrimarySymbol(addr)
        if(sym is not None):
            exports_list.append(sym.getName())
    return exports_list
common_info=extract_common_info()
imports_list=get_imports()
exports_list=get_exports()
common_info["imports"] = imports_list
common_info["exports"] = exports_list




with open("/root/firmware_analysis_tool/ghidra_output/other_info_2.json", "w") as file:
    json.dump(common_info, file, indent=4) 
# def get_entry_point_address():
#     # 获取当前程序的实例
#     program = currentProgram
#     # 使用 getAddressOfEntryPoint() 方法获取入口地址
#     entry_point_address = program.getAddressOfEntryPoint()
    
#     # 输出入口地址
#     print("文件入口地址：", entry_point_address)

# # 调用函数
# get_entry_point_address()





