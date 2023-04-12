import json,difflib

from rAIversing.Engine import rAIverseEngine
from rAIversing.Ghidra_Custom_API import binary_to_c_code, import_changes_to_ghidra_project
from rAIversing.pathing import *

similarity_indicators = [
    "send",
    "get",
    "encode",
    "decode",
    "set",
    "init",
    "process",
    "time",
    "device",
    "memory",
    "hash",
    "encrypt",
    "decrypt",
    "parse",
    "print",
    "setup",
    "alarm",
    "alloc",
    "error",
    "write",
    "read",
    "find",
    "string",
    "free",
    "flag",
    "message",
    "call",
    "char"
]


def eval_p2im_firmwares(ai_module):
    usable_binaries = ["Heat_Press", "CNC", "Gateway"]  # os.listdir(f"{BINARIES_ROOT}/p2im")
    for binary in usable_binaries:
        binary_path = f"{BINARIES_ROOT}/p2im/stripped/{binary}"
        print(f"Processing {binary}")
        if True:
            binary_to_c_code(binary_path, "ARM:LE:32:Cortex")
            raie = rAIverseEngine(ai_module, binary_path=binary_path)
            raie.load_functions()
            raie.run_recursive_rev()
            raie.export_processed(all_functions=True)

        import_changes_to_ghidra_project(binary_path)

    for binary in usable_binaries:
        binary_path = f"{BINARIES_ROOT}/p2im/original/{binary}_original"
        binary_to_c_code(binary_path, "ARM:LE:32:Cortex")

    include_all = False
    for binary in usable_binaries:
        direct_comparison_dict = {}
        evaluation_dict = {}

        with open(os.path.join(PROJECTS_ROOT, binary, f"{binary}.json"), "r") as f:
            reversed_functions = json.load(f)
        with open(os.path.join(PROJECTS_ROOT, f"{binary}_original", f"{binary}_original.json"), "r") as f:
            original_functions = json.load(f)

        overall_score = 0
        regarded_functions = len(original_functions.keys())
        for function, data in original_functions.items():
            entrypoint = data["entrypoint"]
            reversed_key = entrypoint.replace("0x", "FUN_")
            if f"thunk_{reversed_key}" in reversed_functions.keys():
                reversed_name = reversed_functions[f"thunk_{reversed_key}"]["current_name"]
            elif reversed_key in reversed_functions.keys():
                reversed_name = reversed_functions[reversed_key]["current_name"]
                direct_comparison_dict[function] = reversed_name
                score = compute_similarity_score(function, reversed_name.replace(f"_{entrypoint}", ""))
                evaluation_dict[entrypoint] = {
                    function: reversed_name,
                    "score": score
                }
                if "nothing" in reversed_name or "FUNC_" in reversed_name:
                    regarded_functions -= 1
                    continue
                overall_score += score
            else:
                found = False
                for key, value in reversed_functions.items():
                    if value["entrypoint"] == entrypoint:
                        reversed_name = value["current_name"]
                        direct_comparison_dict[function] = reversed_name
                        score = compute_similarity_score(function, reversed_name.replace(f"_{entrypoint}", ""))
                        overall_score += score
                        evaluation_dict[entrypoint] = {
                            function: reversed_name,
                            "score": score
                        }
                        found = True
                        break
                if not found:
                    if include_all:
                        direct_comparison_dict[function] = "NOT FOUND"
                        regarded_functions -= 1
                    continue

        with open(os.path.join(PROJECTS_ROOT, binary, f"{binary}_comparison.json"), "w") as f:
            json.dump(direct_comparison_dict, f, indent=4)
        with open(os.path.join(PROJECTS_ROOT, binary, f"{binary}_evaluation.json"), "w") as f:
            json.dump(evaluation_dict, f, indent=4)
        print(f"Overall score for {binary}: {overall_score/regarded_functions}")


def compute_similarity_score(original_function_name, reversed_function_name):
    original_function_name = original_function_name.lower()
    reversed_function_name = reversed_function_name.lower()
    score = 0
    for indicator in similarity_indicators:
        if indicator in original_function_name and indicator in reversed_function_name:
            score += 1
        elif "nothing" in reversed_function_name:
            score += 1
            break
    if score == 0:
        score = difflib.SequenceMatcher(None, original_function_name, reversed_function_name).ratio()
    return score
