#  Dumps all decompiled code to a file
# @author MrMatch246
# @category tooling
# @keybinding
# @menupath Tools.ExtractC
# @toolbar
import json
import sys
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.flatapi import FlatProgramAPI
import ghidra.program.model.listing.Function
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.pcode import HighFunctionDBUtil
from pathing import *
import ghidra.program.model.symbol.SourceType.IMPORTED as IMPORTED

# As we import changes from a file, we mark them as imported and not as user defined

try:
    from ghidra.ghidra_builtins import *
except:
    pass

fpapi = FlatProgramAPI(getState().getCurrentProgram())
fdapi = FlatDecompilerAPI(fpapi)
options = DecompileOptions()
monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.setOptions(options)
ifc.openProgram(getState().getCurrentProgram())

def getLowestFunctionLayer(functions):
    lflList = []
    for name, data in functions.items():
        if not data["improved"]:
            if len(data["code"].split("FUN_")) == 2:
                lflList.append(name)
    return lflList


def renameForAllFunctions(functions, renaming_dict):
    for name, data in functions.items():
        for old, new in renaming_dict.items():
            data["code"] = data["code"].replace(old, new)


def main(export_path=None, export_with_stripped_names=False):
    state = getState()
    project = state.getProject()
    locator = project.getProjectData().getProjectLocator()
    projectMgr = project.getProjectManager()
    activeProject = projectMgr.getActiveProject()
    fm = currentProgram.getFunctionManager()
    funcs = list(fm.getFunctions(True))  # True means 'forward'

    function_metadata = {}

    cCode = ""
    # If you want to export with stripped names, set this to True


    for i in range(len(funcs)):
        func = funcs[i]
        entrypoint = func.getEntryPoint().toString("0x")
        if "{\n                    /* WARNING: Bad instruction - Truncating control flow here */\n  halt_baddata();\n}" in func_to_C(func):
            continue


        if export_with_stripped_names:
            function_name = "FUN_" + entrypoint.replace("0x", "")
        else:
            function_name = func.getName()
        if export_with_stripped_names:
            original_name = func.getName()
            func.setName(function_name, IMPORTED)
            funcs = list(fm.getFunctions(True))
            func = funcs[i]
            code = func_to_C(func)
            func.setName(original_name, IMPORTED)
        else:
            code = func_to_C(func)

        code = code.replace("/* WARNING: Unknown calling convention -- yet parameter storage is locked */", "")
        code = code.replace("/* WARNING: Control flow encountered bad instruction data */", "")
        code = code.replace("/* WARNING: Subroutine does not return */", "")
        code = code.replace("/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */", "")

        function_metadata[function_name] = {}
        function_metadata[function_name]["entrypoint"] = entrypoint
        function_metadata[function_name]["current_name"] = function_name
        function_metadata[function_name]["code"] = code
        function_metadata[function_name]["renaming"] = {}
        function_metadata[function_name]["calling"] = []
        function_metadata[function_name]["called"] = []
        function_metadata[function_name]["improved"] = "FUN_" not in function_name or (function_name not in code and "FUN_" in function_name)
        function_metadata[function_name]["skipped"] = False
        function_metadata[function_name]["imported"] = False
        function_metadata[function_name]["tags"] = []


        for calling in func.getCallingFunctions(getMonitor()):
            function_metadata[function_name]["calling"].append(calling.getName())

        for called in func.getCalledFunctions(getMonitor()):
            function_metadata[function_name]["called"].append(called.getName())

        cCode += "\n////>>" + func.getEntryPoint().toString("0x") + ">>" + function_name + ">>////\n"
        cCode += code

    program_name = str(fpapi.getCurrentProgram()).split(" ")[0].replace(".", "_")


    if export_path is None:
        export_path = os.path.join(PROJECTS_ROOT, program_name)

    if not os.path.exists(export_path):
        os.mkdir(export_path)

    if not export_with_stripped_names:
        with open(os.path.join(export_path, program_name + ".c"), "w") as f:
            f.write(cCode)
            f.close()
    save_file = {
        "functions": function_metadata,
        "layers": [],
        "locked_functions": [],
        "used_tokens": 0
    }
    if export_with_stripped_names:
        program_name += "_stripped"

    with open(os.path.join(export_path, program_name + ".json"), "w") as f:
        f.write(json.dumps(save_file, indent=4))
        f.close()

def get_high_function(func):
    res = ifc.decompileFunction(func, 60, monitor)
    high = res.getHighFunction()
    return high


def get_function_symbols(func):
    hf = get_high_function(func)
    lsm = hf.getLocalSymbolMap()
    return lsm.getSymbols()

def func_to_C(func):
    return ifc.decompileFunction(func, 0, ConsoleTaskMonitor()).getDecompiledFunction().getC()
    #return fdapi.decompile(func)


if __name__ == "__main__":
    args = list(getScriptArgs())
    if len(args) > 1:
        main(str(args[0]), str(args[1]) == "True")
    elif len(args) > 0:
        main(str(args[0]))
    else:
        main()
