# -*- coding: utf-8 -*-
# ExtractSymbolsScript.py
# This script should be placed in the Ghidra/Features/Base/ghidra_scripts directory
# or any directory specified in the Ghidra script directories.


from ghidra.program.model.symbol import SymbolIterator
from ghidra.util.exception import CancelledException
from ghidra.program.model.listing import Program
from ghidra.program.model.address import AddressSetView
from java.io import FileWriter
from ghidra.program.util import DefinedDataIterator
from ghidra.app.util import XReferenceUtil
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.symbol import SymbolTable, SymbolType
import json
from collections import OrderedDict
import sys

# Function to extract symbols and write to a file
def extract_symbols(program):
    symbol_table = program.getSymbolTable()
    # print(symbol_table)
    symbol_list=[]
    all_symbols = symbol_table.getAllSymbols(True)

    for symbol in all_symbols:
        try:
            # Write symbol name and address to the output file

            symbol_info = {
                "symbol_address": str(symbol.getAddress()),
                "symbol_name": str(symbol.getName())
            }
            symbol_list.append(symbol_info)
            
        except CancelledException:
            break
    return symbol_list

def extract_strings():
    string_list=[]
    
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
    baseaddress = program.getImageBase()#基地址

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


# The main function to be called by Ghidra's Python interpreter
if __name__ == '__main__':
    args = getScriptArgs()
    print(args)
    output_file = args[0]
    if len(args) < 1:
        print("Usage: ExtractSymbols.py <output_file>")
        sys.exit(1)
    # print(output_file)
    program = getCurrentProgram()  # Get the current program being analyzed
    common_info=extract_common_info()
    # imports_list=get_imports()
    # exports_list=get_exports()
    common_info["imports"] = get_imports()
    common_info["exports"] = get_exports()
    common_info["symbols"] = extract_symbols(program)
    common_info["strings"] = extract_strings()
    with open(output_file, "w") as file:
        json.dump(common_info, file, indent=4) 