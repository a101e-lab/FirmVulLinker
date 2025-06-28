# -*- coding: utf-8 -*-
# ExtractSymbolsScript.py
# This script should be placed in the Ghidra/Features/Base/ghidra_scripts directory
# or any directory specified in the Ghidra script directories.

from ghidra.program.model.symbol import SymbolIterator
from ghidra.util.exception import CancelledException
from ghidra.program.model.listing import Program
from ghidra.program.model.address import AddressSetView
from java.io import File as JFile
from ghidra.program.util import DefinedDataIterator
from ghidra.app.util import XReferenceUtil
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.symbol import SymbolTable, SymbolType
import json
from collections import OrderedDict
import sys

def extract_symbols(program):
    symbol_table = program.getSymbolTable()
    symbol_list = []
    all_symbols = symbol_table.getAllSymbols(True)

    for symbol in all_symbols:
        try:
            symbol_info = {
                "symbol_address": str(symbol.getAddress()),
                "symbol_name": str(symbol.getName())
            }
            symbol_list.append(symbol_info)
        except CancelledException:
            break
    return symbol_list

def extract_strings():
    string_list = []
    for string in DefinedDataIterator.definedStrings(currentProgram):
        for ref in XReferenceUtil.getXRefList(string):
            string_info = {
                "string_name": str(string),
                "string_ref": str(ref)
            }
            string_list.append(string_info)
    return string_list

def extract_common_info():
    program = currentProgram
    program_name = program.getDomainFile().getName()
    baseaddress = program.getImageBase()

    common_info = OrderedDict()
    common_info["program_name"] = program_name
    common_info["image_baseaddress"] = str(baseaddress)
    common_info["functions"] = []

    func_manager = program.getFunctionManager()
    functions = func_manager.getFunctions(True)
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
    symtab = currentProgram.getSymbolTable()
    exportAddrs = symtab.getExternalEntryPointIterator()
    exports_list = []
    for addr in exportAddrs:
        sym = symtab.getPrimarySymbol(addr)
        if sym is not None:
            exports_list.append(sym.getName())
    return exports_list

def analyze_file(file_path):
    """
    分析单个文件，提取符号信息。
    """
    file = JFile(file_path)
    program = openProgram(file)
    common_info = extract_common_info()
    common_info["imports"] = get_imports()
    common_info["exports"] = get_exports()
    common_info["symbols"] = extract_symbols(program)
    common_info["strings"] = extract_strings()
    return common_info

def main(output_file, input_files):
    """
    主函数，分析输入文件列表并将结果写入输出 JSON 文件。
    """
    results = []
    for file_path in input_files:
        result = analyze_file(file_path)
        results.append(result)
    print(results)
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    print("Results written to {}".format(output_file))

# 示例用法
if __name__ == '__main__':
    args = getScriptArgs()
    if len(args) < 2:
        print("Usage: ExtractSymbols.py <output_file> <input_file1> <input_file2> ...")
        sys.exit(1)

    output_file = args[0]
    input_files = args[1].split(',')

    main(output_file, input_files)