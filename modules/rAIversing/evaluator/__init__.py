from rich.console import Console, CONSOLE_SVG_FORMAT
from rich.table import Table, Column

from rAIversing.Engine import rAIverseEngine
from rAIversing.Ghidra_Custom_API import binary_to_c_code, import_changes_to_existing_project, existing_project_to_c_code
from rAIversing.evaluator.ScoringAlgos import calc_score_v1
from rAIversing.pathing import *
from rAIversing.utils import save_to_json
from rAIversing.evaluator.utils import load_funcs_data, find_entrypoint

# This is a list of mostly verbs that, if present, describe the intended functionality of a function.
# If two functions share the same verb, they are highly likely to be similar.
# For example, if two functions have "send" in their name, they are likely to both send data.
# Or if two functions have "encrypt" in their name, they are likely to both encrypt data.
similarity_indicators = ["send", "get", "encode", "decode", "set", "init", "process", "time", "device", "memory",
    "hash", "checksum", "check", "verify", "update", "convert", "combine"
                                                                "execute", "calculate", "calc", "encrypt", "decrypt",
    "parse", "print", "setup", "alarm", "alloc", "error", "write", "read", "find", "string", "free", "flag", "message",
    "call", "seek", "loop", "execute", "run", "main", "start", "stop", "exit", "return", "check", "verify", "update",
    "convert", "combine", "clear", "list", "char"]

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
similarity_indicator_groups = [[r"^(.*(stop|disable|end).*)+$", r"^(.*(clear){1}.*(bit|flag|memory).*)+$"],
    [r'^(?!.*deactivate).*(?:activate|enable|start).*$',
     r"^(?!.*deactivate).*((set){1}.*?(bit|flag|memory)|(?:activate|enable|start)).*$"]]

# As library functions usually use shorted names (strchr,strrchr), we need to map the common ones
# to their full / natural language styled names (find_character_in_string, find_last_character_in_string).
replacement_dict = {"strchr": "find_character_in_string", "strrchr": "find_last_character_in_string",
    "memcpy": "copy_memory", "memset": "set_memory", "malloc": "allocate_memory", "strcpy": "copy_string",
    "strlen": "string_length", "strcat": "concatenate_strings", "strncat": "concatenate_strings",
    "strcmp": "compare_strings", "strncmp": "compare_strings", "memchr": "find_character_in_memory",
    "memset": "set_memory", "memmove": "move_memory", "div": "divide", "toInt": "convert_to_integer"

}



def create_table():
    result_table = Table(Column(header="Binary", style="bold bright_yellow on grey23"),
        Column(header="Actual\nAll", style="bold cyan1 on grey23", justify="center"),
        Column(header="Actual\nHigher", style="bold cyan2 on grey23", justify="center"),
        Column(header="Actual\nLowest", style="bold cyan3 on grey23", justify="center"),
        Column(header="Best\nCase", style="bold green on grey23", justify="center"),
        Column(header=" Worst\nCase", style="bold red on grey23", justify="center"),
        Column(header="Act/Best", style="bold green1 on grey23", justify="center"),
        Column(header="Actual vs Best (direct)\nAll|hfl", style="bold green1 on grey23", justify="center"),
        Column(header="RPD\nAll|Hfl", style="bold spring_green2 on grey23", justify="center"),
        Column(header="Total\nOrig|Act", style="magenta on grey23", justify="center"),
        Column(header="Counted\nActual", style="magenta1 on grey23"),
        Column(header="Counted\nBest", style="blue on grey23"),
        Column(header="Counted\nWorst", style="magenta3 on grey23"), title="Evaluation Results",
        title_style="bold bright_red on grey23 ", style="on grey23", border_style="bold bright_green",
        header_style="bold yellow1 on grey23", )
    return result_table


def evaluate_p2im(ai_module, console, parallel, usable_binaries):
    for binary in usable_binaries:
        binary_path = f"{BINARIES_ROOT}/p2im/stripped/{binary}"
        console.log(f"[bold bright_green]Evaluating {binary}[/bold bright_green]")
        binary_to_c_code(binary_path, processor_id="ARM:LE:32:Cortex", project_name="Evaluation")

        raie = rAIverseEngine(ai_module, binary_path=binary_path, json_path=f"{PROJECTS_ROOT}/Evaluation/{binary}.json")
        raie.load_save_file()
        raie.max_parallel_functions = parallel
        raie.run_parallel_rev()
        raie.export_processed(all_functions=True)

        if raie.is_import_needed():
            import_changes_to_existing_project(project_location=f"{PROJECTS_ROOT}/Evaluation",
                project_name="Evaluation", binary_name=binary)
    for binary in usable_binaries:
        binary_path = f"{BINARIES_ROOT}/p2im/original/{binary}_original"
        binary_to_c_code(binary_path, processor_id="ARM:LE:32:Cortex", project_name="Evaluation")
        existing_project_to_c_code(project_location=f"{PROJECTS_ROOT}/Evaluation", binary_name=f"{binary}_original",
            project_name="Evaluation", export_with_stripped_names=True)
    for binary in usable_binaries:
        binary_path = f"{BINARIES_ROOT}/p2im/original/{binary}_original"
        console.log(f"[bold green]Processing Ground Truth for {binary}[/bold green]")
        raie = rAIverseEngine(ai_module, binary_path=binary_path,
                              json_path=f"{PROJECTS_ROOT}/Evaluation/{binary}_original_stripped.json")
        raie.load_save_file()
        raie.max_parallel_functions = parallel
        raie.run_parallel_rev()
    for binary in usable_binaries:
        binary_path = f"{BINARIES_ROOT}/p2im/no_propagation/{binary}_no_propagation"
        console.log(f"[bold green]No Propagation Results for {binary}[/bold green]")
        binary_to_c_code(binary_path, processor_id="ARM:LE:32:Cortex", project_name="Evaluation")
        raie = rAIverseEngine(ai_module, binary_path=binary_path,
                              json_path=f"{PROJECTS_ROOT}/Evaluation/{binary}_no_propagation.json")
        raie.load_save_file()
        raie.max_parallel_functions = parallel
        raie.run_parallel_rev(no_propagation=True)
        if raie.is_import_needed():
            import_changes_to_existing_project(project_location=f"{PROJECTS_ROOT}/Evaluation",
                project_name="Evaluation", binary_name=f"{binary}_no_propagation")


def run_comparison(include_all, original_functions, reversed_functions, dc_dict=None, evaluation_dict=None,
                   skip_lfl=False, skip_hfl=False):
    overall_score = 0
    regarded_functions = len(original_functions.keys())
    wrt_to_dicts = False if dc_dict is None or evaluation_dict is None else True
    if skip_hfl and skip_lfl:
        raise Exception("Cannot skip both HFL and LFL")
    for orig_fun_name, orig_data in original_functions.items():
        orig_fun_name = orig_data["current_name"]
        entrypoint = orig_data["entrypoint"]
        reversed_key = entrypoint.replace("0x", "FUN_")
        if reversed_key not in reversed_functions.keys():
            if f"thunk_{reversed_key}" in reversed_functions.keys():
                reversed_key = f"thunk_{reversed_key}"
        if reversed_key in reversed_functions.keys():
            reversed_name = reversed_functions[reversed_key]["current_name"]
        else:
            found = False
            for key, value in reversed_functions.items():
                if value["entrypoint"] == entrypoint:
                    reversed_name = value["current_name"]
                    reversed_key = key
                    found = True
                    break
            if not found:
                if include_all:
                    if wrt_to_dicts:
                        dc_dict[orig_fun_name] = "NOT FOUND"
                regarded_functions -= 1
                continue

        score = calc_score_v1(orig_fun_name, reversed_name, entrypoint)
        if wrt_to_dicts:
            dc_dict[orig_fun_name] = reversed_name
            evaluation_dict[entrypoint] = {orig_fun_name: reversed_name, "score": score}
        if skip_lfl and len(reversed_functions[reversed_key]["called"]) == 0:
            regarded_functions -= 1
            continue
        if skip_hfl and len(reversed_functions[reversed_key]["called"]) != 0:
            regarded_functions -= 1
            continue
        if "nothing" in reversed_name.lower() or "FUNC_" in reversed_name:
            regarded_functions -= 1
            continue
        overall_score += score
    return overall_score, regarded_functions

def build_scoring_args(calculator,direct,original,scoring_args):
    for group, layer in direct.items():
        for orig_name, pred_name in layer.items():
            entrypoint = find_entrypoint(original, orig_name, pred_name)
            scoring_args.append((calculator, orig_name, pred_name, entrypoint, group))


def score_parallel(scoring_args,result_queue):
    try:
        for calculator, orig_name, pred_name, entrypoint, group in scoring_args:
            score = calculator(orig_name, pred_name, entrypoint)
            result_queue.put((group,entrypoint, orig_name, pred_name, score))
    except KeyboardInterrupt:
        return


def calc_relative_percentage_difference(best, worst, actual):
    try:
        range_ = (best*100) - (worst*100)
        difference = (actual*100) - (worst*100)
        return (difference / range_) * 100
    except ZeroDivisionError:
        print("Division by zero!!!!! @ calc_relative_percentage_difference")
        return 0

