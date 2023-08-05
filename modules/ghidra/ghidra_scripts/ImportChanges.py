# loads changes from a file and applies them to the current program
# @author MrMatch246
# @category tooling
# @keybinding
# @menupath Tools.ImportChanges
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

def main(json_file_path=None):
    state = getState()
    project = state.getProject()
    locator = project.getProjectData().getProjectLocator()
    fm = currentProgram.getFunctionManager()
    funcs = list(fm.getFunctions(True))  # True means 'forward'

    program_name = str(fpapi.getCurrentProgram()).split(" ")[0].replace(".", "_")
    if json_file_path is None:
        json_file_path = os.path.join(
            PROJECTS_ROOT, program_name, f"{program_name}.json"
        )
    else:
        json_file_path = os.path.join(json_file_path, f"{program_name}.json")

    save_file = {}
    with open(json_file_path, "r") as f:
        save_file = json.load(f)
        if "functions" in save_file.keys():
            functions_dict = save_file["functions"]
        else:
            functions_dict = save_file

    current_lookup = {}
    original_lookup = {}
    # Lookup tables
    for function_name, data in functions_dict.items():
        current_lookup[function_name] = data["current_name"]
        original_lookup[data["current_name"]] = function_name

    for func in funcs:

        # Getting original function name if it already has been in ghidra
        func_name = str(func.getName())
        if func_name not in current_lookup.keys():
            if func_name in original_lookup:
                func_name = original_lookup[func_name]

        # Renaming if it is present in the json
        if func_name in functions_dict:
            function_data = functions_dict[func_name]
            renaming_dict = function_data["renaming"]
            new_name = function_data["current_name"]

            # We can skip functions that are Skipped in the json
            if function_data["skipped"] or "imported" in function_data.keys() and function_data["imported"]:
                continue

            # We can skip functions that are not improved in the json (This is not really needed but might be useful)
            if not function_data["improved"]:
                continue

            # Renaming the function
            if func.getName() != new_name:
                func.setName(new_name, IMPORTED)
                print(f"Renaming {func_name} to {new_name}")
            # print("Symbols:")

            # Getting symbols and HighFunction
            # Symbols contain register variables besides other things
            hf = get_high_function(func)
            symbols = get_function_symbols(func)

            for high_symbol in symbols:
                # print(high_symbol.getName())
                symname = high_symbol.getName()
                if symname in renaming_dict.keys():
                    new_name = renaming_dict[symname]
                    if new_name == "" or new_name == symname or " " in new_name or "," in new_name:
                        continue
                    symbol = high_symbol.getSymbol()
                    if symbol is None:
                        continue
                    try:
                        symbol.setName(new_name, IMPORTED)


                    except ghidra.util.exception.DuplicateNameException:
                        new_name = f"{new_name}_"
                        try:
                            symbol.setName(new_name, IMPORTED)
                        except ghidra.util.exception.DuplicateNameException:
                            continue

                    except Exception as e:
                        if "NoneType" in str(e):
                            continue
                        print(f"Error while renaming {symname} in function {func_name}")
                        print(e)
                        continue
                                    #print("Symbol Renaming " + symname + " to " + new_name + " in function " + func_name)

            # Committing changes to the database
            HighFunctionDBUtil.commitLocalNamesToDatabase(hf, IMPORTED)
            HighFunctionDBUtil.commitParamsToDatabase(hf, True, IMPORTED)

            # print("Variables:")

            # Getting variables and parameters of the normal function object
            vars_params = []
            vars_params += func.getAllVariables()
            vars_params += func.getParameters()
            vars_params = list(dict.fromkeys(vars_params))
            for var in vars_params:
                var_name = var.getName()
                if var_name in renaming_dict.keys():
                    # print(var.getName())
                    new_name = renaming_dict[var_name]
                    if new_name == "" or new_name == var_name or " " in new_name or "," in new_name:
                        continue
                    try:
                        var.setName(new_name, IMPORTED)
                    except ghidra.util.exception.DuplicateNameException:
                        new_name = f"{new_name}_"
                        try:
                            var.setName(new_name, IMPORTED)
                        except ghidra.util.exception.DuplicateNameException:
                            continue

                                    #print(str(type(var)) + " Renaming " + var_name + " to " + new_name + " in function " + func_name)
                                    #print("Var Renaming " + var_name + " to " + new_name + " in function " + func_name)
            functions_dict[func_name]["imported"] = True

    for func_name, data in functions_dict.items():
        if not data["imported"]:
            functions_dict[func_name]["imported"] = True

    with open(json_file_path, "w") as f:
        if "functions" in save_file.keys():
            save_file["functions"] = functions_dict
        else:
            save_file = functions_dict
        f.write(json.dumps(save_file, indent=4))


def get_high_function(func):
    res = ifc.decompileFunction(func, 60, monitor)
    return res.getHighFunction()


def get_function_symbols(func):
    hf = get_high_function(func)
    lsm = hf.getLocalSymbolMap()
    return lsm.getSymbols()


if __name__ == "__main__":
    if args := list(getScriptArgs()):
        main(str(args[0]))
    else:
        main()
