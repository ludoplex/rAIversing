import json
import os

from rAIversing.pathing import PROJECTS_ROOT, EVALUATION_ROOT
from rAIversing.utils import to_snake_case, locator



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


def collect_pairs(original, predicted, ):
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
        #print(f"{orig_name} -> {predicted_name} in layer {layer_index}")

        pairs[layer_index][orig_name] = predicted_name

    result_pairs = {}
    #remove empty layers
    for layer, pair in pairs.items():
        if len(pair) != 0:
            result_pairs[layer] = pair

    return result_pairs


def get_layers_index(layers, function_name):
    if "FUN" not in function_name:
        function_name = "FUN_" + function_name.replace("0x", "")
    for index, layer in enumerate(layers):
        #print(f"layer {index}")
        if function_name in layer:
            return index
    raise FunctionNotInLayersException(f"Function {function_name} not found in layers")


def collect_partial_scores(scored):
    """
    calculates the score for the higher and lowest layer functions and total score
    :param scored: the scored functions dict (ends up in the *_eval.json file)
    :return: dict of all, hfl and lfl scores and counts
    """
    lfl_sum = 0
    lfl_count = 0
    hfl_sum = 0
    hfl_count = 0
    for group, scores in scored.items():
        for entrypoint, entry in scores.items():
            pred_name = entry["predicted"]
            if "nothing" in pred_name.lower() or "FUNC_" in pred_name:
                continue
            if group == "hfl":
                hfl_sum += entry["score"]
                hfl_count += 1
            else:
                lfl_sum += entry["score"]
                lfl_count += 1
    return {"all": {"score": (hfl_sum + lfl_sum) / (hfl_count + lfl_count), "count": hfl_count + lfl_count},
            "hfl": {"score": hfl_sum / hfl_count, "count": hfl_count},
            "lfl": {"score": lfl_sum / lfl_count, "count": lfl_count}}

def collect_layered_partial_scores(scored):
    """
    calculates the score for the layered functions and total score
    :param scored: the scored functions dict (ends up in the *_eval.json file)
    :param predicted: dict of predicted functions
    :return: dict of all, and layer scores and counts
    """
    result = {}

    for layer_index, scores in scored.items():
        result[layer_index]= {"score": 0, "count": 0}
        for entrypoint, entry in scores.items():
            pred_name = entry["predicted"]
            if "nothing" in pred_name.lower() or "FUNC_" in pred_name:
                continue
            result[layer_index]["score"] += entry["score"]
            result[layer_index]["count"] += 1
        if result[layer_index]["count"] > 0 and result[layer_index]["score"] > 0:
            result[layer_index]["score"] /= result[layer_index]["count"]
        elif result[layer_index]["score"] > 0:
            print(f"Layer {layer_index} has score {result[layer_index]['score']} but count {result[layer_index]['count']}")
            raise Exception("Layer has score but count is 0")

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
