import statistics

import pandas as pd
from matplotlib import pyplot as plt
from rich.console import Console, CONSOLE_SVG_FORMAT
from rich.table import Table, Column

from rAIversing.evaluator.EvaluatorInterface import EvaluatorInterface
from rAIversing.evaluator.ScoringAlgos import calc_score
from rAIversing.evaluator.utils import *
from rAIversing.utils import save_to_json


class LayeredEvaluator(EvaluatorInterface):
    def __init__(self, ai_modules, source_dirs, runs=1, calculation_function=calc_score):
        super().__init__(ai_modules, source_dirs, runs)
        self.calculator = calculation_function
        self.results = {}
        self.save_all = True
        self.console = Console(soft_wrap=True)
        setup_results(self.ai_modules, self.results, self.source_dirs, self.runs)

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
        # self.console.print(self.results)
        self.display_results()

    def display_results(self):
        for ai_module in self.ai_modules:
            model_name = ai_module.get_model_name()
            for source_dir in self.source_dirs:
                self.create_median_results(model_name, source_dir)
                self.create_average_results(model_name, source_dir)
                # self.create_run_results(model_name, source_dir)

    def create_average_results(self, model_name, source_dir):
        source_dir_name = os.path.basename(source_dir)
        usable_binaries = os.listdir(os.path.join(source_dir, "stripped"))
        for binary in usable_binaries:
            title = f"Average {model_name} on {source_dir_name}/{binary} ({self.runs} runs)"
            table = self.create_table(title)
            df_table = self.create_csv_table()
            scores = self.get_average_results(model_name, source_dir_name, binary)
            self.fill_table(table, scores)
            self.fill_table(df_table, scores, do_csv=True)

            export_console = Console(record=True, width=100)
            export_console.print(table)
            export_path = make_run_path(model_name, source_dir, "0", binary)
            export_name = f"Layered_Eval_Avg_{model_name}_{source_dir_name}_{binary}_{self.runs}_runs"
            export_path = os.path.join(export_path, export_name)
            export_console.save_svg(export_path + ".svg",
                                    clear=False,
                                    title="",
                                    code_format=CONSOLE_SVG_FORMAT.replace("{chrome}", ""))
            df_table.to_csv(export_path + ".csv")

            self.plot_dataframe(df_table,title,export_path)

    def create_median_results(self, model_name, source_dir):
        source_dir_name = os.path.basename(source_dir)
        usable_binaries = os.listdir(os.path.join(source_dir, "stripped"))
        for binary in usable_binaries:
            title = f"Median {model_name} on {source_dir_name}/{binary} ({self.runs} runs)"
            table = self.create_table(title)
            df_table = self.create_csv_table()
            scores = self.get_median_results(model_name, source_dir_name, binary)

            self.fill_table(table, scores)
            self.fill_table(df_table, scores, do_csv=True)
            export_console = Console(record=True, width=100)
            export_console.print(table)
            export_path = make_run_path(model_name, source_dir, "0", binary)
            export_name = f"Layered_Eval_Median_{model_name}_{source_dir_name}_{binary}_{self.runs}_runs"
            export_path = os.path.join(export_path, export_name )
            export_console.save_svg(export_path + ".svg",
                                    clear=False,
                                    title="",
                                    code_format=CONSOLE_SVG_FORMAT.replace("{chrome}", ""))
            df_table.to_csv(export_path + ".csv")

            self.plot_dataframe(df_table,title,export_path)

    def collect_cumulative_results(self):
        for ai_module in self.ai_modules:
            model_name = ai_module.get_model_name()
            for source_dir in self.source_dirs:
                source_dir_name = os.path.basename(source_dir)
                for binary in os.listdir(os.path.join(source_dir, "stripped")):
                    self.collect_cumulative_results_atomic(model_name, source_dir_name, binary)

    def collect_cumulative_results_atomic(self, model, source_dir, binary):
        for compare_type in self.get_results(model, source_dir, 1, binary).keys():
            self.results[model][source_dir][0][binary][compare_type] = {}
            for run in range(1, self.runs + 1):
                for layer_index, layer in self.results[model][source_dir][run][binary][compare_type].items():
                    if layer_index not in self.results[model][source_dir][0][binary][compare_type].keys():
                        self.results[model][source_dir][0][binary][compare_type][layer_index] = {"scores": [],
                                                                                                 "counts": []}
                    self.results[model][source_dir][0][binary][compare_type][layer_index]["scores"].append(
                        layer["score"])
                    self.results[model][source_dir][0][binary][compare_type][layer_index]["counts"].append(
                        layer["count"])

            for layer_index, layer in self.results[model][source_dir][0][binary][compare_type].items():
                self.results[model][source_dir][0][binary][compare_type][layer_index]["score"] = sum(
                    self.results[model][source_dir][0][binary][compare_type][layer_index]["scores"]) / self.runs
                self.results[model][source_dir][0][binary][compare_type][layer_index]["count"] = sum(
                    self.results[model][source_dir][0][binary][compare_type][layer_index]["counts"]) / self.runs

    def get_results(self, model_name, source_dir_name, run, binary):
        return self.results[model_name][source_dir_name][run][binary]

    def evaluate_atomic(self, run_path, binary):
        # self.console.log(f"Starting evaluation of {binary} in {run_path}")
        predicted_fn, predicted_layers = load_funcs_data(os.path.join(run_path, f"{binary}.json"), get_layers=True)
        original_fn, original_layers = load_funcs_data(os.path.join(run_path, f"{binary}_original.json"),
                                                       get_layers=True)
        best_fn, best_layers = load_funcs_data(os.path.join(run_path, f"{binary}_original_stripped.json"),
                                               get_layers=True)
        worst_fn, worst_layers = load_funcs_data(os.path.join(run_path, f"{binary}_no_propagation.json"),
                                                 get_layers=True)

        predict_direct, predict_scored = self.generate_comparison(original_fn, original_layers, predicted_fn,
                                                                  predicted_layers)
        best_direct, best_scored = self.generate_comparison(original_fn, original_layers, best_fn, predicted_layers)
        worst_direct, worst_scored = self.generate_comparison(original_fn, original_layers, worst_fn, predicted_layers)
        best_vs_predict_direct, best_vs_predict_scored = self.generate_comparison(best_fn, best_layers, predicted_fn,
                                                                                  predicted_layers)

        # self.console.log(f"Inserting prediction results for {binary} in {run_path}")
        self.insert_result(run_path, collect_layered_partial_scores(predict_scored), "pred")
        # self.console.log(f"Inserting best results for {binary} in {run_path}")
        self.insert_result(run_path, collect_layered_partial_scores(best_scored), "best")
        # self.console.log(f"Inserting worst results for {binary} in {run_path}")
        self.insert_result(run_path, collect_layered_partial_scores(worst_scored), "worst")
        # self.console.log(f"Inserting best vs prediction results for {binary} in {run_path}")
        self.insert_result(run_path, collect_layered_partial_scores(best_vs_predict_scored), "best_vs_pred")
        self.insert_result(run_path, {"original": {"score": 0, "count": len(original_fn)},
                                      "predicted": {"score": 0, "count": len(predicted_fn)}}, "total_count")

        save_to_json(predict_direct, os.path.join(run_path, f"{binary}_comp.json"))
        save_to_json(predict_scored, os.path.join(run_path, f"{binary}_scored.json"))
        save_to_json(best_direct, os.path.join(run_path, f"{binary}_best-comp.json"))
        save_to_json(worst_direct, os.path.join(run_path, f"{binary}_worst-comp.json"))

        if self.save_all:
            save_to_json(worst_scored, os.path.join(run_path, f"{binary}_worst-scored.json"))
            save_to_json(best_scored, os.path.join(run_path, f"{binary}_best-scored.json"))
            save_to_json(best_vs_predict_direct, os.path.join(run_path, f"{binary}_best_vs_pred-comp.json"))
            save_to_json(best_vs_predict_scored, os.path.join(run_path, f"{binary}_best_vs_pred-scored.json"))

    def generate_comparison(self, original_fn, original_layers, predicted_fn, predicted_layers):
        direct = collect_layered_pairs(original_fn, original_layers, predicted_fn, predicted_layers)
        scored = {}
        for layer_index, layer in direct.items():
            scored[layer_index] = {}
            for orig_name, pred_name in layer.items():
                entrypoint = find_entrypoint(original_fn, orig_name, pred_name)
                score = self.calculator(orig_name, pred_name, entrypoint)
                scored[layer_index][entrypoint] = {"original": orig_name, "predicted": pred_name,
                                                   "score": score}  # Had to change this format as otherwise it could break if original name is "score"  # and this allows for easier access to the data when collecting lfl/hfl
        return direct, scored

    def insert_result(self, run_path, result, compare_type):
        model_name, source_dir_name, run, binary = split_run_path(run_path)
        # self.console.log(f"Inserting {result} for {compare_type} in {run_path}")
        self.results[model_name][source_dir_name][run][binary][compare_type] = result

    def fill_table(self, table, scores, do_csv=False):
        score_previous_layer = 0
        for layer_name, layer in scores["pred"].items():
            score_pred = scores["pred"][layer_name]["score"]
            count_pred = scores["pred"][layer_name]["count"]

            score_best = scores["best"][layer_name]["score"]
            count_best = scores["best"][layer_name]["count"]

            score_worst = scores["worst"][layer_name]["score"]
            count_worst = scores["worst"][layer_name]["count"]

            score_best_vs_pred_direct = scores["best_vs_pred"][layer_name]["score"]

            total_orig = scores["total_count"]["original"]["count"]
            total_pred = scores["total_count"]["predicted"]["count"]

            try:
                score_best_vs_pred = score_pred / score_best
            except ZeroDivisionError:
                if score_pred == 0:
                    score_best_vs_pred = 0

            try:
                score_change = (score_pred - score_previous_layer) / score_previous_layer
            except ZeroDivisionError:
                score_change = score_pred

            if not do_csv:
                table.add_row(f"{layer_name}",
                              f"{score_pred * 100:.2f}%",
                              f"{score_best * 100:.2f}%",
                              f"{score_worst * 100:.2f}%",
                              f"{score_best_vs_pred * 100:.2f}%",
                              f"{score_best_vs_pred_direct * 100:.2f}%",
                              f"{score_change * 100:.2f}%",
                              f"{count_pred}",
                              f"{count_best}",
                              f"{count_worst}"
                              )
            else:
                table.loc[int(layer_name)]=pd.Series({
                    "Layer": int(layer_name),
                    "Actual": float(f"{score_pred * 100:.2f}"),
                    "Best Case": float(f"{score_best * 100:.2f}"),
                    "Worst Case": float(f"{score_worst * 100:.2f}"),
                    "Act/Best": float(f"{score_best_vs_pred * 100:.2f}"),
                    "Act vs Best (direct)": float(f"{score_best_vs_pred_direct * 100:.2f}"),
                    "Change": float(f"{score_change * 100:.2f}"),
                    "Counted Actual": float(f"{count_pred}"),
                    "Counted Best": float(f"{count_best}"),
                    "Counted Worst": float(f"{count_worst}")
                })

            score_previous_layer = score_pred


    def create_table(self, title):
        result_table = Table(Column(header="Layer", style="bold bright_yellow on grey23"),
                             Column(header="Actual", style="bold cyan1 on grey23", justify="center"),
                             Column(header="Best\nCase", style="bold green on grey23", justify="center"),
                             Column(header="Worst\nCase", style="bold red on grey23", justify="center"),
                             Column(header="Act/Best", style="bold green1 on grey23", justify="center"),
                             Column(header="Act vs Best\n(direct)", style="bold green1 on grey23", justify="center"),
                             Column(header="Change", style="bold spring_green2 on grey23", justify="center"),
                             Column(header="Counted\nActual", style="magenta1 on grey23"),
                             Column(header="Counted\nBest", style="blue on grey23"),
                             Column(header="Counted\nWorst", style="magenta3 on grey23"), title=title,
                             title_style="bold bright_red on grey23 ", style="on grey23",
                             border_style="bold bright_green", header_style="bold yellow1 on grey23", )
        return result_table

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

    def get_average_results(self, model_name, source_dir, binary):
        return self.results[model_name][source_dir][0][binary]

    def create_csv_table(self):
        csv_table = pd.DataFrame(columns=["Layer",
                                          "Actual",
                                          "Best Case",
                                          "Worst Case",
                                          "Act/Best",
                                          "Act vs Best (direct)",
                                          "Change",
                                          "Counted Actual",
                                          "Counted Best",
                                          "Counted Worst"])
        return csv_table

    def plot_dataframe(self, df,title,export_path):
        fig = df.plot(x="Layer", y=["Actual", "Best Case", "Worst Case", "Act vs Best (direct)"], title=title)
        fig.figure.savefig(export_path+".png")
