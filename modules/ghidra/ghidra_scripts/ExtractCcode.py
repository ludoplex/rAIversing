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
from ghidra.util.task import ConsoleTaskMonitor

from pathing import *

try:
    from ghidra.ghidra_builtins import *
except:
    pass

fpapi = FlatProgramAPI(getState().getCurrentProgram())
fdapi = FlatDecompilerAPI(fpapi)


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


def main(export_path=None):
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
    export_with_stripped_names = False

    for i in range(len(funcs)):
        func = funcs[i]
        entrypoint = func.getEntryPoint().toString("0x")
        if export_with_stripped_names:
            function_name = "FUN_" + entrypoint.replace("0x", "")
        else:
            function_name = func.getName()
        if export_with_stripped_names:
            code = fdapi.decompile(func).replace(func.getName(), function_name)
        else:
            code = fdapi.decompile(func)

        function_metadata[function_name] = {}
        function_metadata[function_name]["current_name"] = function_name
        function_metadata[function_name]["calling"] = []
        function_metadata[function_name]["called"] = []
        function_metadata[function_name]["code"] = code
        function_metadata[function_name]["entrypoint"] = entrypoint
        function_metadata[function_name]["improved"] = "FUN_" not in function_name
        function_metadata[function_name]["skipped"] = False
        function_metadata[function_name]["renaming"] = {}
        function_metadata[function_name]["imported"] = False


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

    with open(os.path.join(export_path, program_name + ".c"), "w") as f:
        f.write(cCode)
        f.close()
    with open(os.path.join(export_path, program_name + ".json"), "w") as f:
        f.write(json.dumps(function_metadata))
        f.close()


if __name__ == "__main__":
    args = list(getScriptArgs())
    if len(args) > 0:
        main(str(args[0]))
    else:
        main()
