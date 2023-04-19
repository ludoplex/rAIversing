import json,difflib,re

from rAIversing.Engine import rAIverseEngine
from rAIversing.Ghidra_Custom_API import binary_to_c_code, import_changes_to_ghidra_project
from rAIversing.pathing import *




# This is a list of mostly verbs that, if present, describe the intended functionality of a function.
# If two functions share the same verb, they are highly likely to be similar.
# For example, if two functions have "send" in their name, they are likely to both send data.
# Or if two functions have "encrypt" in their name, they are likely to both encrypt data.
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
    "checksum",
    "check",
    "verify",
    "update",
    "convert",
    "combine"
    "execute",
    "calculate",
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
    "seek",
    "loop",
    "execute",
    "char"
]

# The following are groups of similarity indicators that are likely to be used together,
# and regarding that the modell (chatGPT) currently produces rather natural language as function names,
# whereas the debug symbols are rather short and often not very descriptive,
# or just more abstract and not on the machine level,
# we can map a one or more "words" or "sentences" to one or more natural language styled "words" or "sentences".
# For example, if the debug symbol contains "activate" or "start", we can map it to "set...bit" or "set...flag",
# which are more likely to be used in the natural language styled function names.
# Another example would be "deactivate" or "stop", which we can map to "clear...bit" or "clear...flag".
# This is a list of lists, where each list contains a list of regexes that are likely to be used together.
# TODO sendData -> write..Memory/...
# TODO receiveData -> read..Memory/... ???
# TODO DeInit -> free???/deactivate...Memory/... ???
# TODO memcpy -> copy...Memory/... ???
similarity_indicator_groups = [
    [r"^(.*(stop|disable|end).*)+$",r"^(.*(clear){1}.*(bit|flag|memory).*)+$"],
    [r'^(?!.*deactivate).*(?:activate|enable|start).*$',r"^(?!.*deactivate).*((set){1}.*?(bit|flag|memory)|(?:activate|enable|start)).*$"],
]

# As library functions usually use shorted names (strchr,strrchr), we need to map the common ones
# to their full / natural language styled names (find_character_in_string, find_last_character_in_string).






def eval_p2im_firmwares(ai_module,parallel=1):
    usable_binaries = os.listdir(f"{BINARIES_ROOT}/p2im/stripped")# ["Heat_Press", "CNC", "Gateway"]
    for binary in usable_binaries:
        binary_path = f"{BINARIES_ROOT}/p2im/stripped/{binary}"
        print(f"Processing {binary}")
        if True:
            binary_to_c_code(binary_path, "ARM:LE:32:Cortex")
            raie = rAIverseEngine(ai_module, binary_path=binary_path)
            raie.load_save_file()
            raie.max_parallel_functions = parallel
            raie.run_parallel_rev()
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
            reversed_functions = json.load(f)["functions"]
        with open(os.path.join(PROJECTS_ROOT, f"{binary}_original", f"{binary}_original.json"), "r") as f:
            original_functions = json.load(f)["functions"]

        overall_score = 0
        regarded_functions = len(original_functions.keys())
        for function, data in original_functions.items():
            function = data["current_name"]
            entrypoint = data["entrypoint"]
            reversed_key = entrypoint.replace("0x", "FUN_")
            if f"thunk_{reversed_key}" in reversed_functions.keys():
                reversed_name = reversed_functions[f"thunk_{reversed_key}"]["current_name"]
            elif reversed_key in reversed_functions.keys():
                reversed_name = reversed_functions[reversed_key]["current_name"]
                direct_comparison_dict[function] = reversed_name
                score = compute_similarity_score(function, reversed_name,entrypoint)
                evaluation_dict[entrypoint] = {
                    function: reversed_name,
                    "score": score
                }
                if "nothing" in reversed_name.lower() or "FUNC_" in reversed_name:
                    regarded_functions -= 1
                    continue
                overall_score += score
            else:
                found = False
                for key, value in reversed_functions.items():
                    if value["entrypoint"] == entrypoint:
                        reversed_name = value["current_name"]
                        direct_comparison_dict[function] = reversed_name
                        score = compute_similarity_score(function, reversed_name,entrypoint)
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
        print(f"Overall score for {binary}: {overall_score/regarded_functions} ({regarded_functions} functions regarded out of {len(original_functions.keys())} total)")


def compute_similarity_score(original_function_name, reversed_function_name,entrypoint):
    original_function_name = original_function_name.lower().replace(f"_{entrypoint.replace('0x','')}", "")
    reversed_function_name = reversed_function_name.lower().replace(f"_{entrypoint.replace('0x','')}", "")
    score = 0.0
    #remove duplicates from similarity_indicators
    similarity_indicators_local = list(set(similarity_indicators))

    for indicator in similarity_indicators:
        if indicator in original_function_name and indicator in reversed_function_name:
            score += 1.0
        elif "nothing" in reversed_function_name:
            score += 1.0
            break
    if score == 0.0:
        score = calc_group_similarity(original_function_name, reversed_function_name)
    if score == 0.0:
        score = difflib.SequenceMatcher(None, original_function_name, reversed_function_name).ratio()
    return score

def calc_group_similarity(original_function_name, reversed_function_name):
    for group in similarity_indicator_groups:
        if re.match(group[0], original_function_name) and re.match(group[1], reversed_function_name):
            return 1.0
    return 0.0