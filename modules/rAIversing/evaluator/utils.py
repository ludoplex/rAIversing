import json
import os

from rAIversing.pathing import PROJECTS_ROOT, EVALUATION_ROOT
from rAIversing.utils import to_snake_case


def load_funcs_data(file):
    """
    if file is not a path to a file, it is assumed to be relative to PROJECTS_ROOT
    :param file:
    """
    if not os.path.exists(file):
        file = os.path.join(PROJECTS_ROOT, file)
    with open(file, "r") as f:
        save_file = json.load(f)
        functions = save_file["functions"]
    return functions


def make_run_path(model_name, source_dir, run, binary):
    return os.path.join(EVALUATION_ROOT, model_name, os.path.basename(source_dir), f"run_{run}" if run != "" else "", binary)


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


def collect_partial_scores(scored, predicted):
    """
    calculates the score for the higher and lowest layer functions and total score
    :param scored: the scored functions dict (ends up in the *_eval.json file)
    :param predicted: dict of predicted functions
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


def find_entrypoint(funcs, current_name):
    for key, func in funcs.items():
        if func["current_name"] == current_name:
            return func["entrypoint"]
    raise Exception(f"Entrypoint for {current_name} not found")


def tokenize_name_v1(name):
    return to_snake_case(name).split("_")
