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
import sys

# sys.setdefaultencoding() does not exist, here!
reload(sys)  # Reload does the trick!
sys.setdefaultencoding('UTF8')

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

halt_bad_data = "{\n                    /* WARNING: Bad instruction - Truncating control flow here */\n  halt_baddata();\n}"


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
    program_name = fpapi.getProgramFile().getName()
    state = getState()
    project = state.getProject()
    locator = project.getProjectData().getProjectLocator()
    projectMgr = project.getProjectManager()
    activeProject = projectMgr.getActiveProject()
    fm = currentProgram.getFunctionManager()
    funcs = list(fm.getFunctions(True))  # True means 'forward'

    if export_path is None:
        export_path = os.path.join(PROJECTS_ROOT, program_name)
    else:
        if not program_name.replace("_no_propagation", "").replace("_original", "") in \
               export_path.split("/")[-1].split("\\")[-1]:
            export_path = os.path.join(export_path,
                                       program_name.replace("_no_propagation", "").replace("_original", ""))
    export_path = export_path.replace('"', "")

    if os.path.exists(os.path.join(export_path, program_name + ".json")):
        if export_with_stripped_names:
            program_name_temp = program_name + "_stripped"
            if os.path.exists(os.path.join(export_path, program_name_temp + ".json")):
                print("#@#@#@#@#@#@#")
                return
        else:
            print("#@#@#@#@#@#@#")
            return
    function_metadata = {}

    cCode = "".encode("utf-8")

    if len(funcs) > 700 and True:
        print("More than 700 functions in " + program_name + ". exiting!")
        with open(os.path.join(export_path, "not_extracted"), "w") as f:
            f.write("More than 700 functions in " + program_name + ". exiting!")
        print("#@#@#@#@#@#@#")
        return

    for i in range(len(funcs)):
        func = funcs[i]
        entrypoint = func.getEntryPoint().toString("0x")
        try:
            if halt_bad_data in func_to_C(func):
                continue
        except Exception as e:
            print(e)
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
        # print("Decompiled " + function_name)
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
        function_metadata[function_name]["improved"] = "FUN_" not in function_name or (
                function_name not in code and "FUN_" in function_name)
        function_metadata[function_name]["skipped"] = False
        function_metadata[function_name]["imported"] = False
        function_metadata[function_name]["tags"] = []

        for calling in func.getCallingFunctions(getMonitor()):
            function_metadata[function_name]["calling"].append(calling.getName())

        for called in func.getCalledFunctions(getMonitor()):
            function_metadata[function_name]["called"].append(called.getName())

        cCode += ("\n////>>" + func.getEntryPoint().toString("0x") + ">>" + function_name + ">>////\n").encode(
            "utf-8").decode("utf-8")

        cCode += code.encode("utf-8").decode("utf-8")

    program_name = str(fpapi.getCurrentProgram()).split(" ")[0].replace(".", "_")

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

    if not os.path.exists(os.path.join(export_path, program_name + ".json")):
        with open(os.path.join(export_path, program_name + ".json"), "w") as f:
            f.write(json.dumps(save_file, indent=4))
            f.close()
    print("#@#@#@#@#@#@#")


def get_high_function(func):
    res = ifc.decompileFunction(func, 60, monitor)
    high = res.getHighFunction()
    return high


def get_function_symbols(func):
    hf = get_high_function(func)
    lsm = hf.getLocalSymbolMap()
    return lsm.getSymbols()


def func_to_C(func):
    try:
        return ifc.decompileFunction(func, 0, ConsoleTaskMonitor()).getDecompiledFunction().getC().encode("utf-8").decode("utf-8")
    except:
        try:
            print("Ding!")
            return fdapi.decompile(func).encode("utf-8").decode("utf-8")
        except:
            print("Dong!")
            return halt_bad_data


if __name__ == "__main__":
    args = list(getScriptArgs())

    if len(args) > 1:
        main(str(args[0]), str(args[1]) == "True")
    elif len(args) > 0:
        main(str(args[0]))
    else:
        main()
