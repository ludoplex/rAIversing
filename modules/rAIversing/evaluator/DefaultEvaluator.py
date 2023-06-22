import os
import statistics

from rich.console import Console, CONSOLE_SVG_FORMAT
from rich.table import Table, Column
from rAIversing.evaluator.EvaluatorInterface import EvaluatorInterface
from rAIversing.evaluator.ScoringAlgos import calc_score_v2
from rAIversing.evaluator.utils import *
from rAIversing.evaluator import load_funcs_data, calc_score_v1, calc_relative_percentage_difference
from rAIversing.pathing import REPO_ROOT
from rAIversing.utils import save_to_json, save_to_csv
import pandas as pd


class DefaultEvaluator(EvaluatorInterface):
    def __init__(self, ai_modules, source_dirs, runs=1, calculation_function=calc_score_v2):
        super().__init__(ai_modules, source_dirs, runs)
        self.calculator = calculation_function
        self.results = {}
        self.save_all = False
        self.console = Console(soft_wrap=True)
        self.setup_results()

    def setup_results(self):
        """
        Sets up the run_results dictionary, which is used to store the results of the evaluation
        Cumulative results are stored in run 0
        """
        for ai_module in self.ai_modules:
            model_name = ai_module.get_model_name()
            self.results[model_name] = {}
            for source_dir in self.source_dirs:
                source_dir_name = os.path.basename(source_dir)
                self.results[model_name][source_dir_name] = {}
                for run in range(0, self.runs + 1):  # NOTE: cumulative results are stored in run 0
                    self.results[model_name][source_dir_name][run] = {}
                    for binary in os.listdir(os.path.join(source_dir, "stripped")):
                        self.results[model_name][source_dir_name][run][binary] = {}

    def set_calculator(self, calculation_function):
        self.calculator = calculation_function

    def evaluate(self):
        for ai_module in self.ai_modules:
            model_name = ai_module.get_model_name()
            for source_dir in self.source_dirs:
                source_dir_name = os.path.basename(source_dir)
                for run in range(1, self.runs + 1):
                    for binary in os.listdir(os.path.join(source_dir, "stripped")):
                        self.evaluate_atomic(make_run_path(model_name, source_dir_name, run, binary), binary)
        self.collect_cumulative_results()
        self.display_results()

    def evaluate_atomic(self, run_path, binary):

        predicted_fn = load_funcs_data(os.path.join(run_path, f"{binary}.json"))
        original_fn = load_funcs_data(os.path.join(run_path, f"{binary}_original.json"))
        best_fn = load_funcs_data(os.path.join(run_path, f"{binary}_original_stripped.json"))
        worst_fn = load_funcs_data(os.path.join(run_path, f"{binary}_no_propagation.json"))

        predict_direct, predict_scored = self.generate_comparison(original_fn, predicted_fn)
        best_direct, best_scored = self.generate_comparison(original_fn, best_fn)
        worst_direct, worst_scored = self.generate_comparison(original_fn, worst_fn)
        best_vs_predict_direct, best_vs_predict_scored = self.generate_comparison(best_fn, predicted_fn)

        self.insert_result(run_path, collect_partial_scores(predict_scored, predicted_fn), "pred")
        self.insert_result(run_path, collect_partial_scores(best_scored, best_fn), "best")
        self.insert_result(run_path, collect_partial_scores(worst_scored, worst_fn), "worst")
        self.insert_result(run_path, collect_partial_scores(best_vs_predict_scored, predicted_fn), "best_vs_pred")
        self.insert_result(run_path, {"original": {"score": 0, "count": len(original_fn)},
                                      "predicted": {"score": 0, "count": len(predicted_fn)}}, "total_count")

        save_to_json(predict_direct, os.path.join(run_path, f"{binary}_comp.json"))
        save_to_json(predict_scored, os.path.join(run_path, f"{binary}_scored.json"))
        save_to_json(best_direct, os.path.join(run_path, f"{binary}_best_comp.json"))
        save_to_json(worst_direct, os.path.join(run_path, f"{binary}_worst_comp.json"))

        if self.save_all:
            save_to_json(worst_scored, os.path.join(run_path, f"{binary}_worst_scored.json"))
            save_to_json(best_scored, os.path.join(run_path, f"{binary}_best_scored.json"))
            save_to_json(best_vs_predict_direct, os.path.join(run_path, f"{binary}_best_vs_pred_comp.json"))
            save_to_json(best_vs_predict_scored, os.path.join(run_path, f"{binary}_best_vs_pred_scored.json"))

    def generate_comparison(self, original, predicted):
        direct = collect_pairs(original, predicted)
        scored = {"hfl": {}, "lfl": {}}
        for group, layer in direct.items():
            for orig_name, pred_name in layer.items():
                try:
                    entrypoint = original[orig_name]["entrypoint"]
                except KeyError:
                    if orig_name.split("_")[-1] == pred_name.split("_")[-1]:
                        entrypoint = "0x" + (orig_name.split("_")[-1])
                    else:
                        entrypoint = find_entrypoint(original, orig_name)
                score = self.calculator(orig_name, pred_name, entrypoint)
                scored[group][entrypoint] = {"original": orig_name, "predicted": pred_name,
                                             "score": score}  # Had to change this format as otherwise it could break if original name is "score"  # and this allows for easier access to the data when collecting lfl/hfl
        return direct, scored

    def insert_result(self, run_path, result, group):
        model_name, source_dir_name, run, binary = split_run_path(run_path)
        self.results[model_name][source_dir_name][run][binary][group] = result

    def collect_cumulative_results(self):
        for ai_module in self.ai_modules:
            model_name = ai_module.get_model_name()
            for source_dir in self.source_dirs:
                source_dir_name = os.path.basename(source_dir)
                for binary in os.listdir(os.path.join(source_dir, "stripped")):
                    self.collect_cumulative_results_atomic(model_name, source_dir_name, binary)

    def collect_cumulative_results_atomic(self, model, source_dir, binary):
        for comp_type in self.get_results(model, source_dir, 1, binary).keys():
            self.results[model][source_dir][0][binary][comp_type] = {}
            for run in range(1, self.runs + 1):
                for group, layer in self.results[model][source_dir][run][binary][comp_type].items():
                    if group not in self.results[model][source_dir][0][binary][comp_type].keys():
                        self.results[model][source_dir][0][binary][comp_type][group] = {"scores": [], "counts": []}
                    self.results[model][source_dir][0][binary][comp_type][group]["scores"].append(layer["score"])
                    self.results[model][source_dir][0][binary][comp_type][group]["counts"].append(layer["count"])

            for group, layer in self.results[model][source_dir][0][binary][comp_type].items():
                self.results[model][source_dir][0][binary][comp_type][group]["score"] = sum(
                    self.results[model][source_dir][0][binary][comp_type][group]["scores"]) / self.runs
                self.results[model][source_dir][0][binary][comp_type][group]["count"] = sum(
                    self.results[model][source_dir][0][binary][comp_type][group]["counts"]) / self.runs

    def get_results(self, model_name, source_dir_name, run, binary):
        return self.results[model_name][source_dir_name][run][binary]

    def get_average_results(self, model_name, source_dir, binary):
        return self.results[model_name][source_dir][0][binary]

    def get_median_results(self, model_name, source_dir_name, binary):
        scores = dict(self.results[model_name][source_dir_name][0][binary].copy())
        output = {}
        for group_name, group in scores.items():
            output[group_name] = {}
            for layer_name, layer in group.items():
                output[group_name][layer_name] = {}
                output[group_name][layer_name]["score"] = statistics.median(layer["scores"])
                output[group_name][layer_name]["count"] = statistics.median(layer["counts"])
        return output

    def display_results(self):
        for ai_module in self.ai_modules:
            model_name = ai_module.get_model_name()
            for source_dir in self.source_dirs:
                self.create_median_results(model_name, source_dir)
                self.create_average_results(model_name, source_dir)
                # self.create_run_results(model_name, source_dir)

    def create_run_results(self, model_name, source_dir):
        source_dir_name = os.path.basename(source_dir)
        usable_binaries = os.listdir(os.path.join(source_dir, "stripped"))
        # usable_binaries = ["CNC"]  # TODO remove
        for run in range(1, self.runs + 1):
            table = self.create_table(f"{model_name} on {source_dir_name} (Run {run})")
            for binary in usable_binaries:
                scores = self.get_results(model_name, source_dir_name, run, binary)
                self.fill_table(table, scores, binary)
            export_console = Console(record=True, width=160)
            export_console.print(table)
            run_path = make_run_path(model_name, source_dir, run, "")
            export_console.save_svg(os.path.join(run_path, f"Eval_{model_name}_{source_dir_name}_run_{run}.svg"),
                                    clear=False, title="",
                                    code_format=CONSOLE_SVG_FORMAT.replace("{chrome}", ""))

    def create_average_results(self, model_name, source_dir):
        source_dir_name = os.path.basename(source_dir)
        table = self.create_table(f"Average {model_name} on {source_dir_name} ({self.runs} runs)")
        usable_binaries = os.listdir(os.path.join(source_dir, "stripped"))
        for binary in usable_binaries:
            scores = self.get_average_results(model_name, source_dir_name, binary)
            self.fill_table(table, scores, binary)
        export_console = Console(record=True, width=165)
        export_console.print(table)
        export_path = make_run_path(model_name, source_dir, "", "")
        export_console.save_svg(
            os.path.join(export_path, f"Eval_Avg_{model_name}_{source_dir_name}_{self.runs}_runs.svg"), clear=False,
            title="",
            code_format=CONSOLE_SVG_FORMAT.replace("{chrome}", ""))

    def create_median_results(self, model_name, source_dir):
        source_dir_name = os.path.basename(source_dir)
        table = self.create_table(f"Median {model_name} on {source_dir_name} ({self.runs} runs)")
        usable_binaries = os.listdir(os.path.join(source_dir, "stripped"))
        for binary in usable_binaries:
            scores = self.get_median_results(model_name, source_dir_name, binary)

            self.fill_table(table, scores, binary)
        export_console = Console(record=True, width=165)
        export_console.print(table)
        export_path = make_run_path(model_name, source_dir, "", "")
        export_console.save_svg(
            os.path.join(export_path, f"Eval_Median_{model_name}_{source_dir_name}_{self.runs}_runs.svg"), clear=False,
            title="",
            code_format=CONSOLE_SVG_FORMAT.replace("{chrome}", ""))

    def create_table(self, title):
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

    def fill_table(self, table, scores, binary):
        # self.console.print(scores)

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
