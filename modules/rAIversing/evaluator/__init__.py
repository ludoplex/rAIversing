import json, difflib, re
from rich.console import Console,CONSOLE_SVG_FORMAT
from rich.table import Table, Column


from rAIversing.Engine import rAIverseEngine
from rAIversing.Ghidra_Custom_API import binary_to_c_code, import_changes_to_ghidra_project, \
    import_changes_to_existing_project, existing_project_to_c_code
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
    "calc",
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
    "run",
    "main",
    "start",
    "stop",
    "exit",
    "return",
    "check",
    "verify",
    "update",
    "convert",
    "combine",
    "clear",
    "list",
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
# main -> run ... ???
# validate -> check... ???
similarity_indicator_groups = [
    [r"^(.*(stop|disable|end).*)+$", r"^(.*(clear){1}.*(bit|flag|memory).*)+$"],
    [r'^(?!.*deactivate).*(?:activate|enable|start).*$',
     r"^(?!.*deactivate).*((set){1}.*?(bit|flag|memory)|(?:activate|enable|start)).*$"]
]

# As library functions usually use shorted names (strchr,strrchr), we need to map the common ones
# to their full / natural language styled names (find_character_in_string, find_last_character_in_string).
replacement_dict = {
    "strchr": "find_character_in_string",
    "strrchr": "find_last_character_in_string",
    "memcpy": "copy_memory",
    "memset": "set_memory",
    "malloc": "allocate_memory",
    "strcpy": "copy_string",
    "strlen": "string_length",
    "strcat": "concatenate_strings",
    "strncat": "concatenate_strings",
    "strcmp": "compare_strings",
    "strncmp": "compare_strings",
    "memchr": "find_character_in_memory",
    "memset": "set_memory",
    "memmove": "move_memory",
    "div": "divide",
    "toInt": "convert_to_integer"


}

def eval_p2im_firmwares(ai_module, parallel=1):
    usable_binaries = os.listdir(f"{BINARIES_ROOT}/p2im/stripped")  # ["Heat_Press", "CNC", "Gateway"]
    #usable_binaries = ["Heat_Press", "CNC", "Gateway"]
    console = Console(soft_wrap=True)
    for binary in usable_binaries:
        binary_path = f"{BINARIES_ROOT}/p2im/stripped/{binary}"
        console.log(f"[bold bright_green]Evaluating {binary}[/bold bright_green]")
        if True:
            binary_to_c_code(binary_path,processor_id= "ARM:LE:32:Cortex",project_name="Evaluation")
            raie = rAIverseEngine(ai_module, binary_path=binary_path,json_path=f"{PROJECTS_ROOT}/Evaluation/{binary}.json")
            raie.load_save_file()
            raie.max_parallel_functions = parallel
            raie.run_parallel_rev()
            raie.export_processed(all_functions=True)

        import_changes_to_existing_project(project_location=f"{PROJECTS_ROOT}/Evaluation",project_name="Evaluation",binary_name=binary)

    for binary in usable_binaries:
        binary_path = f"{BINARIES_ROOT}/p2im/original/{binary}_original"
        binary_to_c_code(binary_path,processor_id="ARM:LE:32:Cortex",project_name="Evaluation")
        existing_project_to_c_code(project_location=f"{PROJECTS_ROOT}/Evaluation",binary_name=f"{binary}_original",project_name="Evaluation",export_with_stripped_names=True)

    for binary in usable_binaries:
        binary_path = f"{BINARIES_ROOT}/p2im/original/{binary}_original"
        console.print(f"[bold green]Processing Ground Truth for {binary}[/bold green]")
        if True:
            raie = rAIverseEngine(ai_module, binary_path=binary_path,json_path=f"{PROJECTS_ROOT}/Evaluation/{binary}_original_stripped.json")
            raie.load_save_file()
            raie.max_parallel_functions = parallel
            raie.run_parallel_rev()





    include_all = False

    result_table = Table(
        Column(header="Binary", style="bold bright_yellow on grey23"),
        Column(header="Model vs Orig", style="bold cyan1 on grey23"),
        Column(header="GTruth vs Orig", style="bold cyan2 on grey23"),
        Column(header="Model vs GTruth", style="bold green1 on grey23"),
        Column(header="Regarded Orig", style="blue on grey23"),
        Column(header="Regarded GTruth", style="magenta on grey23"),
        title="Evaluation Results",title_style="bold dark_red on grey23 ",
        style="on grey23",
        header_style="bold bright_yellow on grey23",
        )




    for binary in usable_binaries:
        direct_comparison_dict = {}
        evaluation_dict = {}
        reversed_functions = {}
        original_functions = {}
        ground_truth_functions = {}
        direct_comparison_dict_GT = {}
        evaluation_dict_GT = {}

        with open(os.path.join(PROJECTS_ROOT, "Evaluation", f"{binary}.json"), "r") as f:
            save_file = json.load(f)
            if "functions" in save_file.keys():
                reversed_functions = save_file["functions"]
            else:
                reversed_functions = save_file
        with open(os.path.join(PROJECTS_ROOT, f"Evaluation", f"{binary}_original.json"), "r") as f:
            save_file = json.load(f)
            if "functions" in save_file.keys():
                original_functions = save_file["functions"]
            else:
                original_functions = save_file
        with open(os.path.join(PROJECTS_ROOT, f"Evaluation", f"{binary}_original_stripped.json"), "r") as f:
            save_file = json.load(f)
            if "functions" in save_file.keys():
                ground_truth_functions = save_file["functions"]
            else:
                ground_truth_functions = save_file

        overall_score_original, regarded_functions_original = run_comparison(include_all, original_functions, reversed_functions, direct_comparison_dict, evaluation_dict)
        overall_score_ground_truth, regarded_functions_ground_truth = run_comparison(include_all, ground_truth_functions, reversed_functions, direct_comparison_dict_GT, evaluation_dict_GT)

        with open(os.path.join(PROJECTS_ROOT, "Evaluation", f"{binary}_comparison.json"), "w") as f:
            json.dump(direct_comparison_dict, f, indent=4)
        with open(os.path.join(PROJECTS_ROOT,"Evaluation", f"{binary}_evaluation.json"), "w") as f:
            json.dump(evaluation_dict, f, indent=4)

        with open(os.path.join(PROJECTS_ROOT, "Evaluation", f"{binary}_GT_comparison.json"), "w") as f:
            json.dump(direct_comparison_dict_GT, f, indent=4)
        with open(os.path.join(PROJECTS_ROOT,"Evaluation", f"{binary}_GT_evaluation.json"), "w") as f:
            json.dump(evaluation_dict_GT, f, indent=4)

        score_original = overall_score_original / regarded_functions_original
        score_ground_truth = overall_score_ground_truth / regarded_functions_ground_truth
        score_gt_vs_original = score_original/score_ground_truth
        result_table.add_row(binary, f"{score_original:.2f}", f"{score_ground_truth:.2f}", f"{score_gt_vs_original:.2f}", f"{regarded_functions_original}/{len(original_functions.keys())}", f"{regarded_functions_ground_truth}/{len(ground_truth_functions.keys())}")

    export_console= Console(record=True,width=120)
    export_console.print(result_table)
    export_console.save_svg(os.path.join(REPO_ROOT, f"evaluation_results.svg"),clear=False,title="",code_format=CONSOLE_SVG_FORMAT.replace("{chrome}",""))




def run_comparison(include_all, original_functions, reversed_functions, direct_comparison_dict, evaluation_dict):
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
            score = compute_similarity_score(function, reversed_name, entrypoint)
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
                    score = compute_similarity_score(function, reversed_name, entrypoint)
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
    return overall_score, regarded_functions


def compute_similarity_score(original_function_name, reversed_function_name, entrypoint):
    original_function_name = original_function_name.lower().replace(f"_{entrypoint.replace('0x', '')}", "")
    reversed_function_name = reversed_function_name.lower().replace(f"_{entrypoint.replace('0x', '')}", "")
    score = 0.0
    # remove duplicates from similarity_indicators
    similarity_indicators_local = list(set(similarity_indicators))

    for indicator in similarity_indicators:
        if indicator in original_function_name and indicator in reversed_function_name:
            score = 1.0
            break
        elif "nothing" in reversed_function_name:
            score = 1.0
            break
    if score == 0.0:
        score = calc_group_similarity(original_function_name, reversed_function_name)

    for old, new in replacement_dict.items():
        if new not in original_function_name and old == original_function_name:
            original_function_name = original_function_name.replace(old, new)
            break
    if score == 0.0:
        for indicator in similarity_indicators:
            if indicator in original_function_name and indicator in reversed_function_name:
                score = 1.0
                break
            elif "nothing" in reversed_function_name:
                score = 1.0
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
