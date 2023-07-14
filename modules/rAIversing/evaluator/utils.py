import json
import math
import os

import pandas
import pandas as pd
from rich.table import Table, Column

from rAIversing.pathing import PROJECTS_ROOT, EVALUATION_ROOT
from rAIversing.utils import to_snake_case, locator
from cairosvg import svg2png


class FunctionNotInLayersException(Exception):
    """Raised when a function is not Found in any Layer, usually indicating that it was skipped due to size or do_nothing"""


def load_funcs_data(file, get_layers=False):
    """
    if file is not a path to a file, it is assumed to be relative to PROJECTS_ROOT
    :param file:
    """
    if not os.path.exists(file):
        file = os.path.join(PROJECTS_ROOT, file)
    with open(file, "r") as f:
        save_file = json.load(f)
        functions = save_file["functions"]
        layers = save_file["layers"]
    if get_layers:
        return functions, layers
    else:
        return functions


def make_run_path(model_name, source_dir, run, binary):
    return os.path.join(EVALUATION_ROOT, model_name, os.path.basename(source_dir), f"run_{run}" if run != "" else "",
                        binary)


def split_run_path(run_path):
    model_name, source_dir, run, binary = run_path.split(os.path.sep)[-4:]
    return model_name, source_dir, int(run.replace("run_", "")), binary


def collect_pairs(original, predicted):
    """
    finds the corresponding function names between two lists of functions
    :param original: list of functions
    :param predicted: list of functions
    :return: dict of pairs of function names grouped by high and low layer functions
    """
    pairs = {"hfl": {}, "lfl": {}}
    for orig_name, orig_data in original.items():
        orig_name = orig_data["current_name"]
        entrypoint = orig_data["entrypoint"]
        predicted_key = entrypoint.replace("0x", "FUN_")
        if predicted_key not in predicted.keys():
            if f"thunk_{predicted_key}" in predicted.keys():
                predicted_key = f"thunk_{predicted_key}"
        elif orig_name in predicted.keys():
            predicted_key = orig_name
        if predicted_key in predicted.keys():
            predicted_name = predicted[predicted_key]["current_name"]
        else:
            found = False
            for key, predicted_data in predicted.items():
                if predicted_data["entrypoint"] == entrypoint:
                    predicted_name = predicted_data["current_name"]
                    predicted_key = key
                    found = True
                    break
            if not found:
                continue
        if len(predicted[predicted_key]["called"]) != 0:
            pairs["hfl"][orig_name] = predicted_name
        else:
            pairs["lfl"][orig_name] = predicted_name

    return pairs


def collect_layered_pairs(original_fn, original_layers, predicted_fn, predicted_layers):
    """
    finds the corresponding function names between two lists of functions
    :param original_fn: list of functions
    :param predicted_fn: list of functions
    :return: dict of pairs of function names grouped by layer
    """
    pairs = {}
    for x in range(0, len(predicted_layers)):
        pairs[x] = {}
    if len(predicted_layers) == 0:
        print(original_layers)
        print(predicted_layers)
        print(predicted_fn)
        raise Exception("No layers found")

    for orig_name, orig_data in original_fn.items():
        predicted_name = ""
        orig_name = orig_data["current_name"]
        entrypoint = orig_data["entrypoint"]
        predicted_key = entrypoint.replace("0x", "FUN_")
        if predicted_key not in predicted_fn.keys():
            if f"thunk_{predicted_key}" in predicted_fn.keys():
                predicted_key = f"thunk_{predicted_key}"
        elif orig_name in predicted_fn.keys():
            predicted_key = orig_name
        if predicted_key in predicted_fn.keys():
            predicted_name = predicted_fn[predicted_key]["current_name"]
        else:
            found = False
            for key, predicted_data in predicted_fn.items():
                if predicted_data["entrypoint"] == entrypoint:
                    predicted_name = predicted_data["current_name"]
                    predicted_key = key
                    found = True
                    break
            if not found:
                continue
        try:
            layer_index = get_layers_index(predicted_layers, predicted_key)
        except FunctionNotInLayersException:

            continue
        except Exception as e:
            print(e)
            raise e
        # print(f"{orig_name} -> {predicted_name} in layer {layer_index}")

        pairs[layer_index][orig_name] = predicted_name

    result_pairs = {}
    # remove empty layers
    for layer, pair in pairs.items():
        if len(pair) != 0:
            result_pairs[layer] = pair

    return result_pairs


def get_layers_index(layers, function_name):
    if "FUN" not in function_name:
        function_name = "FUN_" + function_name.replace("0x", "")
    for index, layer in enumerate(layers):
        # print(f"layer {index}")
        if function_name in layer:
            return index
    raise FunctionNotInLayersException(f"Function {function_name} not found in layers")


def check_extracted(model_name, source_dir_name, binary):
    """
    checks if the binary has been extracted
    or if it has been skipped due too many functions
    TODO fix this whole too many functions thing for eval runs
    :param model_name:
    :param source_dir_name:
    :param binary:
    :return:
    """
    run_path = os.path.join(EVALUATION_ROOT, model_name, source_dir_name, "extraction", binary)
    return not os.path.exists(os.path.join(run_path, "not_extracted"))


def collect_partial_scores(scored):
    """
    calculates the score for the higher and lowest layer functions and total score
    :param scored: the scored functions dict (ends up in the *_eval.json file)
    :return: dict of all, hfl and lfl scores and counts
    """
    debug = False
    lfl_sum = 0
    lfl_count = 0
    hfl_sum = 0
    hfl_count = 0

    layer = 0
    for group, scores in scored.items():
        for entrypoint, entry in scores.items():
            pred_name = entry["predicted"]
            if "nothing" in pred_name.lower() or "FUNC_" in pred_name or \
                    ("reverse" in pred_name and "engineer" in pred_name) or \
                    ("improve" in pred_name and "function" in pred_name):
                if debug:
                    print(f"skipping {pred_name}")
                continue
            if layer == 0:
                hfl_sum += entry["score"]
                hfl_count += 1
            else:
                lfl_sum += entry["score"]
                lfl_count += 1
        layer += 1
    return {"all": {"score": ((hfl_sum + lfl_sum) / (hfl_count + lfl_count)) if (hfl_count + lfl_count) else 0,
                    "count": hfl_count + lfl_count},
            "hfl": {"score": (hfl_sum / hfl_count) if hfl_count else 0
                , "count": hfl_count},
            "lfl": {"score": (lfl_sum / lfl_count) if lfl_count else 0, "count": lfl_count}}


def collect_layered_partial_scores(scored, bucket_factor=0.0):
    """
    calculates the score for the layered functions and total score for each bucket
    :param scored: the scored functions dict (ends up in the *_eval.json file)
    :param predicted: dict of predicted functions
    :return: dict of all, and layer scores and counts
    """
    layer_indices = list(scored.keys())
    layers_left = len(layer_indices)
    debug = False
    max_layer = len(layer_indices) - 1
    result = {}
    current_bucket = 0
    layer_key = current_bucket if bucket_factor == 0.0 else layers_str_for_bucket(current_bucket, bucket_factor,
                                                                                  max_layer)
    while layers_left > 0:
        for i in range(num_layers_for_bucket(current_bucket, bucket_factor)):
            layer_index = layer_indices.pop(0)
            layer = scored[layer_index]
            if layer_key not in result.keys():
                result[layer_key] = {"score": 0, "count": 0}
            for entrypoint, entry in layer.items():
                pred_name = entry["predicted"]
                if "nothing" in pred_name.lower() or "FUNC_" in pred_name or \
                        ("reverse" in pred_name and "engineer" in pred_name) or \
                        ("improve" in pred_name and "function" in pred_name):
                    if debug:
                        print(f"skipping {pred_name}")
                    continue
                result[layer_key]["score"] += entry["score"]
                result[layer_key]["count"] += 1
            layers_left -= 1
            if layers_left == 0:
                break
        if result[layer_key]["count"] > 0 and result[layer_key]["score"] > 0:
            result[layer_key]["score"] /= result[layer_key]["count"]
        elif result[layer_key]["score"] > 0:
            print(
                f"Bucket {current_bucket} has score {result[current_bucket]['score']} but count {result[current_bucket]['count']}")
            raise Exception("Bucket has score but count is 0")
        current_bucket += 1
        layer_key = current_bucket if bucket_factor == 0.0 else layers_str_for_bucket(current_bucket, bucket_factor,
                                                                                      max_layer)

    return result


def find_entrypoint(original_fn, orig_name, pred_name):
    try:
        entrypoint = original_fn[orig_name]["entrypoint"]
    except KeyError:
        if orig_name.split("_")[-1] == pred_name.split("_")[-1]:
            entrypoint = "0x" + (orig_name.split("_")[-1])
        else:
            for key, func in original_fn.items():
                if func["current_name"] == orig_name:
                    entrypoint = func["entrypoint"]
                    break
            if entrypoint is None:
                raise Exception(f"Entrypoint for {orig_name} not found")
    return entrypoint


def tokenize_name_v1(name):
    return to_snake_case(name).split("_")


def setup_results(ai_modules, results, source_dirs, runs):
    """
    Sets up the run_results dictionary, which is used to store the results of the evaluation
    Cumulative results are stored in run 0
    """
    for ai_module in ai_modules:
        model_name = ai_module.get_model_name()
        results[model_name] = {}
        for source_dir in source_dirs:
            source_dir_name = os.path.basename(source_dir)
            results[model_name][source_dir_name] = {}
            for run in range(0, runs + 1):  # NOTE: cumulative results are stored in run 0
                results[model_name][source_dir_name][run] = {}
                for binary in os.listdir(os.path.join(source_dir, "stripped")):
                    results[model_name][source_dir_name][run][binary] = {}


def build_scoring_args(calculator, direct, original, scoring_args):
    for group, layer in direct.items():
        for orig_name, pred_name in layer.items():
            entrypoint = find_entrypoint(original, orig_name, pred_name)
            scoring_args.append((calculator, orig_name, pred_name, entrypoint, group))


def score_parallel(scoring_args, result_queue):
    try:
        for calculator, orig_name, pred_name, entrypoint, group in scoring_args:
            score = calculator(orig_name, pred_name, entrypoint)
            result_queue.put((group, entrypoint, orig_name, pred_name, score))
    except KeyboardInterrupt:
        return


def calc_relative_percentage_difference(best, worst, actual):
    try:
        range_ = (best * 100) - (worst * 100)
        difference = (actual * 100) - (worst * 100)
        return (difference / range_) * 100
    except ZeroDivisionError:
        print("Division by zero!!!!! @ calc_relative_percentage_difference")
        return 0.0


def fill_table(table, scores, binary, do_csv=False):
    score_pred = scores["pred"]["all"]["score"]
    score_pred_hfl = scores["pred"]["hfl"]["score"]
    score_pred_lfl = scores["pred"]["lfl"]["score"]
    counted_pred = scores["pred"]["all"]["count"]

    score_best = scores["best"]["all"]["score"]
    score_best_hfl = scores["best"]["hfl"]["score"]
    score_best_lfl = scores["best"]["lfl"]["score"]
    counted_best = scores["best"]["all"]["count"]

    score_worst = scores["worst"]["all"]["score"]
    score_worst_hfl = scores["worst"]["hfl"]["score"]
    score_worst_lfl = scores["worst"]["lfl"]["score"]
    counted_worst = scores["worst"]["all"]["count"]

    score_best_vs_pred_direct = scores["best_vs_pred"]["all"]["score"]
    score_best_vs_pred_direct_hfl = scores["best_vs_pred"]["hfl"]["score"]
    score_best_vs_pred_direct_lfl = scores["best_vs_pred"]["lfl"]["score"]

    total_orig = scores["total_count"]["original"]["count"]
    total_pred = scores["total_count"]["predicted"]["count"]

    score_best_vs_pred = score_pred / score_best
    score_best_vs_pred_hfl = score_pred_hfl / score_best_hfl

    # self.console.print(f"score_best_hfl: {score_best_hfl}, score_worst_hfl: {score_worst_hfl}, score_pred_hfl: {score_pred_hfl}")
    # self.console.print(f"score_best_lfl: {score_best_lfl}, score_worst_lfl: {score_worst_lfl}, score_pred_lfl: {score_pred_lfl}")
    score_rpd_hfl = calc_relative_percentage_difference(score_best_hfl, score_worst_hfl, score_pred_hfl)
    score_rdp_lfl = calc_relative_percentage_difference(score_best_lfl, score_worst_lfl, score_pred_lfl)
    score_rpd = calc_relative_percentage_difference(score_best, score_worst, score_pred)

    if not do_csv:
        table.add_row(binary, f"{score_pred * 100:.2f}%",
                      f"{score_pred_hfl * 100:.2f}%",
                      f"{score_pred_lfl * 100:.2f}%",
                      f"{score_best_hfl * 100:.2f}%",
                      f"{score_worst_hfl * 100:.2f}%",
                      f"{score_best_vs_pred * 100:.1f}%|{score_best_vs_pred_hfl * 100:.1f}%",
                      f"{score_best_vs_pred_direct * 100:.2f}%|{score_best_vs_pred_direct_hfl * 100:.2f}%",
                      f"{score_rpd :.1f}%|{score_rpd_hfl :.1f}%|{score_rdp_lfl :.1f}%",
                      f"{total_orig:.0f}[bold magenta1]|[/bold magenta1]{total_pred:.0f}",
                      f"{counted_pred:.0f}",
                      f"{counted_best:.0f}",
                      f"{counted_worst:.0f}")
    else:
        # ["binary", "actual-all", "actual-hfl", "actual-lfl", "best-case", "worst-case",
        # "act/best-all", "act/best-hfl", "act-vs-best-direct-all",
        # "act-vs-best-direct-hfl", "rpd-all", "rpd-hfl", "rpd-lfl", "total-orig",
        # "total-act", "counted-actual", "counted-best", "counted-worst"]

        table.loc[binary] = pd.Series({
            "binary": binary,
            "actual-all": f"{score_pred * 100:.2f}%",
            "actual-hfl": f"{score_pred_hfl * 100:.2f}%",
            "actual-lfl": f"{score_pred_lfl * 100:.2f}%",
            "best-case": f"{score_best_hfl * 100:.2f}%",
            "worst-case": f"{score_worst_hfl * 100:.2f}%",
            "act/best-all": f"{score_best_vs_pred * 100:.1f}%",
            "act/best-hfl": f"{score_best_vs_pred_hfl * 100:.1f}%",
            "act-vs-best-direct-all": f"{score_best_vs_pred_direct * 100:.2f}%",
            "act-vs-best-direct-hfl": f"{score_best_vs_pred_direct_hfl * 100:.2f}%",
            "rpd-all": f"{score_rpd :.1f}%",
            "rpd-hfl": f"{score_rpd_hfl :.1f}%",
            "rpd-lfl": f"{score_rdp_lfl :.1f}%",
            "total-orig": f"{total_orig:.0f}",
            "total-act": f"{total_pred:.0f}",
            "counted-actual": f"{counted_pred:.0f}",
            "counted-best": f"{counted_best:.0f}",
            "counted-worst": f"{counted_worst:.0f}"
        })


def fill_layered_table(table, scores, do_csv=False):
    score_previous_layer = 0
    bucket_number = 0
    for layer_name, layer in scores["pred-layered"].items():
        score_pred = scores["pred-layered"][layer_name]["score"]
        count_pred = scores["pred-layered"][layer_name]["count"]

        score_best = scores["best-layered"][layer_name]["score"]
        count_best = scores["best-layered"][layer_name]["count"]

        score_worst = scores["worst-layered"][layer_name]["score"]
        count_worst = scores["worst-layered"][layer_name]["count"]

        # This is to catch cases where the direct comparison had different number of layers and the last bucket of
        # "best_vs_pred-layered" is not the same as the last bucket of "pred-layered"
        try:
            score_best_vs_pred_direct = scores["best_vs_pred-layered"][layer_name]["score"]
        except KeyError:
            layer_keys = list(scores["best_vs_pred-layered"].keys())
            score_best_vs_pred_direct = scores["best_vs_pred-layered"][layer_keys[-1]]["score"]

        try:
            score_best_vs_pred = score_pred / score_best
        except ZeroDivisionError:
            if score_pred == 0:
                score_best_vs_pred = 0

        if score_previous_layer != 0:
            score_change = (score_pred - score_previous_layer) / score_previous_layer
        else:
            score_change = score_pred

        rdp = calc_relative_percentage_difference(score_best, score_worst, score_pred)

        if not do_csv:
            table.add_row(f"{layer_name}",
                          f"{score_pred * 100:.2f}%",
                          f"{score_best * 100:.2f}%",
                          f"{score_worst * 100:.2f}%",
                          f"{score_best_vs_pred * 100:.2f}%",
                          f"{score_best_vs_pred_direct * 100:.2f}%",
                          f"{rdp:.2f}%",
                          f"{score_change * 100:.2f}%",
                          f"{count_pred}",
                          f"{count_best}",
                          f"{count_worst}"
                          )
        else:
            table.loc[bucket_number] = pd.Series({
                "Bucket": bucket_number,
                "Layer": layer_name,
                "Actual": float(f"{score_pred * 100:.2f}"),
                "Best Case": float(f"{score_best * 100:.2f}"),
                "Worst Case": float(f"{score_worst * 100:.2f}"),
                "Act/Best": float(f"{score_best_vs_pred * 100:.2f}"),
                "Act vs Best (direct)": float(f"{score_best_vs_pred_direct * 100:.2f}"),
                "RDP": float(f"{rdp:.2f}"),
                "Change": float(f"{score_change * 100:.2f}"),
                "Counted Actual": float(f"{count_pred}"),
                "Counted Best": float(f"{count_best}"),
                "Counted Worst": float(f"{count_worst}")
            })
        bucket_number += 1
        score_previous_layer = score_pred


def num_layers_for_bucket(bucket_number, growth_factor=0.0):
    return math.floor(math.pow((1 + growth_factor), bucket_number))


def layers_str_for_bucket(bucket_number, growth_factor=0.0, max_layer=0):
    num_prev_layers = 0
    needed_layers = num_layers_for_bucket(bucket_number, growth_factor)
    for i in range(bucket_number):
        num_prev_layers += num_layers_for_bucket(i, growth_factor)
    bucket_end = min(num_prev_layers + num_layers_for_bucket(bucket_number, growth_factor) - 1, max_layer)
    bucket_start = num_prev_layers
    if needed_layers == 1 or bucket_start == bucket_end:
        return f"{num_prev_layers}"
    else:
        return f"{bucket_start}-{bucket_end}"


def svg_2_png(svg_path):
    with open(svg_path + ".svg", "r") as svg_file:
        svg = svg_file.read()
    svg2png(bytestring=svg, write_to=svg_path + ".png")
    os.remove(svg_path + ".svg")


def plot_layered_multi_dataframe(axis, df: pandas.DataFrame, title):
    df.plot(ax=axis, title=title, x="Bucket",
            y=["Best Case", "Actual", "Worst Case", "RDP", "Act/Best"],
            color=["green", "darkorange", "red", "mediumturquoise", "darkorchid"]).set_ylim(
        0, 110)
    return len(df["Bucket"])


def plot_dataframe(df: pandas.DataFrame, title, export_path):
    fig = df.plot.bar(x="Layer", y=["Best Case", "Actual", "Worst Case", "RDP", "Act/Best"],
                      title=title, figsize=(len(df["Layer"]) * 2, 8), layout=("tight"), width=0.8,
                      color=["green", "darkorange", "red", "mediumturquoise", "darkorchid"]).get_figure()
    fig.figure.savefig(export_path + ".png")


def create_table(title):
    result_table = Table(Column(header="Binary", style="bold bright_yellow on grey23"),
                         Column(header="Actual\nAll", style="bold cyan1 on grey23", justify="center"),
                         Column(header="Actual\nHigher", style="bold cyan2 on grey23", justify="center"),
                         Column(header="Actual\nLowest", style="bold cyan3 on grey23", justify="center"),
                         Column(header="Best\nCase", style="bold green on grey23", justify="center"),
                         Column(header=" Worst\nCase", style="bold red on grey23", justify="center"),
                         Column(header="Act/Best\nAll|Hfl", style="bold green1 on grey23", justify="center"),
                         Column(header="Act vs Best\n(direct)\nAll|Hfl", style="bold green1 on grey23",
                                justify="center"),
                         Column(header="RPD\nAll|Hfl|Lfl", style="bold spring_green2 on grey23", justify="center"),
                         Column(header="Total\nOrig|Act", style="magenta on grey23", justify="center"),
                         Column(header="Counted\nActual", style="magenta1 on grey23"),
                         Column(header="Counted\nBest", style="blue on grey23"),
                         Column(header="Counted\nWorst", style="magenta3 on grey23"), title=title,
                         title_style="bold bright_red on grey23 ", style="on grey23",
                         border_style="bold bright_green", header_style="bold yellow1 on grey23", )
    return result_table


def create_csv_table():
    result_table = pd.DataFrame(columns=["binary", "actual-all", "actual-hfl", "actual-lfl", "best-case", "worst-case",
                                         "act/best-all", "act/best-hfl", "act-vs-best-direct-all",
                                         "act-vs-best-direct-hfl", "rpd-all", "rpd-hfl", "rpd-lfl", "total-orig",
                                         "total-act", "counted-actual", "counted-best", "counted-worst"])
    return result_table


def create_layered_table(title):
    result_table = Table(Column(header="Layer", style="bold bright_yellow on grey23"),
                         Column(header="Actual", style="bold cyan1 on grey23", justify="center"),
                         Column(header="Best\nCase", style="bold green on grey23", justify="center"),
                         Column(header="Worst\nCase", style="bold red on grey23", justify="center"),
                         Column(header="Act/Best", style="bold green1 on grey23", justify="center"),
                         Column(header="Act vs Best\n(direct)", style="bold green1 on grey23", justify="center"),
                         Column(header="RPD", style="bold spring_green2 on grey23", justify="center"),
                         Column(header="Change", style="bold spring_green2 on grey23", justify="center"),
                         Column(header="Counted\nActual", style="magenta1 on grey23"),
                         Column(header="Counted\nBest", style="blue on grey23"),
                         Column(header="Counted\nWorst", style="magenta3 on grey23"), title=title,
                         title_style="bold bright_red on grey23 ", style="on grey23",
                         border_style="bold bright_green", header_style="bold yellow1 on grey23", )
    return result_table


def create_layered_csv_table():
    csv_table = pd.DataFrame(columns=["Bucket",
                                      "Layer",
                                      "Actual",
                                      "Best Case",
                                      "Worst Case",
                                      "Act/Best",
                                      "Act vs Best (direct)",
                                      "RDP",
                                      "Change",
                                      "Counted Actual",
                                      "Counted Best",
                                      "Counted Worst"])
    return csv_table
