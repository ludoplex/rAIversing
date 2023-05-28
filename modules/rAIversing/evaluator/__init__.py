from rich.console import Console, CONSOLE_SVG_FORMAT
from rich.table import Table, Column

from rAIversing.Engine import rAIverseEngine
from rAIversing.Ghidra_Custom_API import binary_to_c_code, import_changes_to_existing_project, existing_project_to_c_code
from rAIversing.evaluator.ScoringAlgos import calc_score_v1
from rAIversing.pathing import *
from rAIversing.utils import save_to_json
from rAIversing.evaluator.utils import load_funcs_data

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


def eval_p2im_firmwares(ai_module, parallel=1):
    usable_binaries = os.listdir(f"{BINARIES_ROOT}/p2im/stripped")  # ["Heat_Press", "CNC", "Gateway"]
    # usable_binaries = ["Heat_Press", "CNC", "Gateway"]
    console = Console(soft_wrap=True)

    evaluate_p2im(ai_module, console, parallel, usable_binaries)

    include_all = False

    result_table = create_table()
    postfix = ""
    if postfix != "":
        postfix = f"_{postfix}_"
    for binary in usable_binaries:
        console.log(f"[bold bright_green]Evaluating {binary}{postfix}[/bold bright_green]")
        dc_dict = {}
        eval_dict = {}
        funcs_actual = {}
        funcs_orig = {}
        funcs_no_prop = {}
        funcs_gt = {}
        dc_dict_GT = {}
        eval_dict_GT = {}
        dc_dict_hfl = {}
        eval_dict_hfl = {}
        dc_dict_no_prop = {}
        eval_dict_no_prop = {}

        funcs_actual = load_funcs_data(f"Evaluation/{binary}.json")
        funcs_orig = load_funcs_data(f"Evaluation/{binary}_original.json")
        funcs_gt = load_funcs_data(f"Evaluation/{binary}_original_stripped.json")
        funcs_no_prop = load_funcs_data(f"Evaluation/{binary}_no_propagation.json")

        sum_actual, counted_actual = run_comparison(include_all, funcs_orig, funcs_actual, dc_dict, eval_dict)
        score_actual = sum_actual / counted_actual

        sum_hfl, counted_hfl = run_comparison(include_all, funcs_orig, funcs_actual, dc_dict_hfl, eval_dict_hfl,
            skip_lfl=True)
        score_hfl = sum_hfl / counted_hfl

        sum_lfl, counted_lfl = run_comparison(include_all, funcs_orig, funcs_actual, skip_hfl=True)
        score_lfl = sum_lfl / counted_lfl

        sum_ground_truth_hfl, counted_ground_truth = run_comparison(include_all, funcs_orig, funcs_gt, dc_dict_GT,
            eval_dict_GT, skip_lfl=True)
        score_best_hfl = sum_ground_truth_hfl / counted_ground_truth

        sum_ground_truth_all, counted_ground_truth = run_comparison(include_all, funcs_orig, funcs_gt)
        score_best_all = sum_ground_truth_all / counted_ground_truth

        sum_no_prop_hfl, counted_no_prop = run_comparison(include_all, funcs_orig, funcs_no_prop, dc_dict_no_prop,
            eval_dict_no_prop, skip_lfl=True)
        score_worst_hfl = sum_no_prop_hfl / counted_no_prop

        sum_no_prop, counted_no_prop = run_comparison(include_all, funcs_orig, funcs_no_prop)
        score_worst_all = sum_no_prop / counted_no_prop

        sum_gt_vs_actual_direct_all, counted_gt_vs_actual = run_comparison(include_all, funcs_gt, funcs_actual)
        score_gt_vs_actual_dir_all = sum_gt_vs_actual_direct_all / counted_gt_vs_actual

        sum_gt_vs_actual_direct_hfl, counted_gt_vs_actual = run_comparison(include_all, funcs_gt, funcs_actual,
            skip_lfl=True)
        score_gt_vs_actual_dir_hfl = sum_gt_vs_actual_direct_hfl / counted_gt_vs_actual

        save_to_json(dc_dict, f"Evaluation/{binary}_comp.json")
        save_to_json(eval_dict, f"Evaluation/{binary}_eval.json")
        save_to_json(dc_dict_GT, f"Evaluation/{binary}_best_comp.json")
        save_to_json(eval_dict_GT, f"Evaluation/{binary}_best_eval.json")
        save_to_json(dc_dict_no_prop, f"Evaluation/{binary}_worst_comp.json")
        save_to_json(eval_dict_no_prop, f"Evaluation/{binary}_worst_eval.json")

        score_gt_vs_actual = score_actual / score_best_hfl

        score_rpd_hfl = calc_relative_percentage_difference(score_best_hfl, score_worst_hfl, score_hfl)

        score_rpd_all = calc_relative_percentage_difference(score_best_all, score_worst_all, score_actual)

        result_table.add_row(binary, f"{score_actual * 100:.2f}%", f"{score_hfl * 100:.2f}%", f"{score_lfl * 100:.2f}%",
                             f"{score_best_hfl * 100:.2f}%", f"{score_worst_hfl * 100:.2f}%",
                             f"{score_gt_vs_actual * 100:.2f}%",
                             f"{score_gt_vs_actual_dir_all * 100:.2f}%|{score_gt_vs_actual_dir_hfl * 100:.2f}%",
                             f"{score_rpd_all :.1f}%|{score_rpd_hfl :.1f}%",
                             f"{len(funcs_orig.keys())}[bold magenta1]|[/bold magenta1]{len(funcs_actual.keys())}",
                             f"{counted_actual}", f"{counted_ground_truth}", f"{counted_no_prop}")

    export_console = Console(record=True, width=150)
    export_console.print(result_table)
    export_console.save_svg(os.path.join(REPO_ROOT, f"evaluation_results.svg"), clear=False, title="",
                            code_format=CONSOLE_SVG_FORMAT.replace("{chrome}", ""))


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


def calc_relative_percentage_difference(best, worst, actual):
    range = best - worst
    difference = actual - worst
    return (difference / range) * 100
