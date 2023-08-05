import statistics

from matplotlib import pyplot as plt
from rich.console import Console, CONSOLE_SVG_FORMAT

from rAIversing.evaluator.EvaluatorInterface import EvaluatorInterface
from rAIversing.evaluator.ScoringAlgos import calc_score
from rAIversing.evaluator.utils import *
from rAIversing.evaluator.utils import create_layered_csv_table, create_layered_table
from rAIversing.utils import save_to_json, save_to_csv
from rich.progress import Progress, TimeElapsedColumn
import multiprocessing as mp


class LayeredEvaluator(EvaluatorInterface):
    def __init__(self, ai_modules, source_dirs, runs=1, calculation_function=calc_score, pool_size=1):
        super().__init__(ai_modules, source_dirs, runs, pool_size)
        self.bucket_growth_factor = 0.0
        self.calculator = calculation_function
        self.results = {}
        self.save_all = False
        self.console = Console(soft_wrap=True)
        self.usable_binaries = {}
        setup_results(self.ai_modules, self.results, self.source_dirs, self.runs)

    def set_calculator(self, calculation_function):
        self.calculator = calculation_function

    def evaluate(self, growth_factor=0.0):
        self.bucket_growth_factor = growth_factor
        with Progress(*Progress.get_default_columns(), TimeElapsedColumn(), transient=True,
                      speed_estimate_period=60.0) as progress:
            task_ai_modules = progress.add_task(f"[bold bright_yellow]Evaluating {len(self.ai_modules)} AI modules",
                                                total=len(self.ai_modules))

            self.progress = progress

            for ai_module in self.ai_modules:
                model_name = ai_module.get_model_name()
                self.usable_binaries[model_name] = {}
                task_source_dirs = progress.add_task(
                    f"[bold bright_yellow]Evaluating {len(self.source_dirs)} source directories",
                    total=len(self.source_dirs))

                for source_dir in self.source_dirs:
                    source_dir_name = os.path.basename(source_dir)
                    self.usable_binaries[model_name][source_dir_name] = set()

                    task_runs = progress.add_task(f"[bold bright_yellow]Evaluating {self.runs} runs", total=self.runs)

                    for run in range(1, self.runs + 1):
                        usable_binaries = os.listdir(os.path.join(source_dir, "stripped"))

                        task_binary = progress.add_task(
                            f"[bold bright_yellow]Evaluating {len(usable_binaries)} binaries",
                            total=len(usable_binaries))

                        self.task_binary = task_binary
                        for binary in usable_binaries:
                            if check_extracted(model_name, source_dir_name, binary):
                                self.evaluate_atomic(make_run_path(model_name, source_dir_name, run, binary), binary,
                                                     bucket_growth_factor=self.bucket_growth_factor)
                                self.usable_binaries[model_name][source_dir_name].add(binary)
                            else:
                                self.usable_binaries[model_name][source_dir_name].discard(binary)
                            progress.advance(task_runs, advance=(1 / len(usable_binaries)))
                        progress.remove_task(task_binary)
                        progress.advance(task_source_dirs, advance=(1 / self.runs))
                    progress.remove_task(task_runs)
                    progress.advance(task_ai_modules, advance=(1 / len(self.source_dirs)))
                progress.remove_task(task_source_dirs)
            progress.stop()
            self.collect_cumulative_results()
            # self.console.print(self.results)
            self.display_results()
            self.console.log(
                f"Finished evaluation of {len(self.ai_modules)} AI modules on {len(self.source_dirs)} source directories with {self.runs} runs each with a Bucket Growth Factor of {self.bucket_growth_factor}")

    def display_results(self):
        for ai_module in self.ai_modules:
            model_name = ai_module.get_model_name()
            for source_dir in self.source_dirs:
                self.create_all_results(model_name, source_dir)
                # self.create_layered_median_results(model_name, source_dir)
                # self.create_layered_average_results(model_name, source_dir)
                # self.create_run_results(model_name, source_dir)

    def create_all_results(self, model_name, source_dir):
        source_dir_name = os.path.basename(source_dir)
        usable_binaries = sorted(self.usable_binaries[model_name][source_dir_name])

        # Table that contains results for all binaries in a source directory no layering
        median_table = create_table(f"Median {model_name} on {source_dir_name} ({self.runs} runs)")
        median_df_table = create_csv_table()

        # Table that contains results for all binaries in a source directory with layering
        median_layered_fig, median_layered_axes = plt.subplots(nrows=len(usable_binaries), ncols=1,
                                                               figsize=(10, len(usable_binaries) * 4), layout=("tight"))

        size_max = 0
        axis_max = 0

        for axes_index, binary in enumerate(usable_binaries):
            # Table and DataFrame for a single binary with layering
            single_median_title = f"Median {model_name} on {source_dir_name}/{binary} ({self.runs} runs)"
            single_median_layered_table = create_layered_table(single_median_title)
            single_median_df_table = create_layered_csv_table()

            # Scores for a single binary
            median_scores = self.get_median_results(model_name, source_dir_name, binary)

            # Fill tables with scores
            fill_layered_table(single_median_layered_table, median_scores)
            fill_layered_table(single_median_df_table, median_scores, do_csv=True)
            fill_table(median_table, median_scores, binary)
            fill_table(median_df_table, median_scores, binary, do_csv=True)

            # Setup results export for the median_layered_table
            median_export_console = Console(record=True, width=100)
            median_export_console.print(single_median_layered_table)

            # File Type agnostic export path
            export_path = os.path.join(make_run_path(model_name, source_dir, "0", binary)
                                       ,
                                       f"Layered_Eval_Median_{model_name}_{source_dir_name}_{binary}_{self.runs}_runs")
            # Export results for the median_layered_table
            median_export_console.save_svg(
                f"{export_path}.svg",
                clear=False,
                title="",
                code_format=CONSOLE_SVG_FORMAT.replace("{chrome}", ""),
            )
            # Convert svg to png and delete svg
            svg_2_png(export_path)

            # Export csv
            single_median_df_table.to_csv(f"{export_path}.csv")

            # Plot results for the median_df_table
            plot_dataframe(single_median_df_table, single_median_title, export_path)
            median_layered_axes[axes_index].set_xmargin(0.0)

            # Add plot to figure that contains all plots for a source directory with layering
            size_curr = plot_layered_multi_dataframe(median_layered_axes[axes_index], single_median_df_table, binary)

            # For finding the plot with the longest x axis
            if size_curr > size_max:
                axis_max = axes_index
            size_max = max(size_curr, size_max)
        # Setup results export that contains results for all binaries in a source directory no layering
        median_export_console = Console(record=True, width=180)
        median_export_console.print(median_table)

        # File Type agnostic export path
        export_path = os.path.join(make_run_path(model_name, source_dir, "0", ""),
                                   f"Eval_Median_{model_name}_{source_dir_name}_{self.runs}_runs")
        # Export results for the median_table
        median_export_console.save_svg(
            f"{export_path}.svg",
            code_format=CONSOLE_SVG_FORMAT.replace("{chrome}", ""),
        )
        svg_2_png(export_path)

        # Export csv
        median_df_table.to_csv(f"{export_path}.csv")

        # Fix missing tick labels and share longest x axis
        for a in median_layered_fig.axes:
            a.sharex(median_layered_axes[axis_max])
            a.tick_params(
                axis='x',  # changes apply to the x-axis
                which='both',  # both major and minor ticks are affected
                bottom=True,
                top=False,
                labelbottom=True)  # labels along the bottom edge are on
        # Save figure that contains all plots for a source directory with layering as png
        median_layered_fig.savefig(
            os.path.join(make_run_path(model_name, source_dir, "0", ""),
                         f"Layered_Eval_Median_{model_name}_{source_dir_name}_{self.runs}_runs.png")
        )
        plt.close()

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
                scores = self.results[model][source_dir][0][binary][compare_type][layer_index]["scores"]
                score = statistics.mean(scores)
                self.results[model][source_dir][0][binary][compare_type][layer_index]["score"] = score
                counts = self.results[model][source_dir][0][binary][compare_type][layer_index]["counts"]
                count = statistics.mean(counts)
                self.results[model][source_dir][0][binary][compare_type][layer_index]["count"] = count

    def get_results(self, model_name, source_dir_name, run, binary):
        return self.results[model_name][source_dir_name][run][binary]

    def evaluate_atomic(self, run_path, binary, bucket_growth_factor=0.0):
        # self.console.log(f"Starting evaluation of {binary} in {run_path}")
        predicted_fn, predicted_layers = load_funcs_data(os.path.join(run_path, f"{binary}.json"), get_layers=True)
        original_fn, original_layers = load_funcs_data(os.path.join(run_path, f"{binary}_original.json"),
                                                       get_layers=True)
        best_fn, best_layers = load_funcs_data(os.path.join(run_path, f"{binary}_original_stripped.json"),
                                               get_layers=True)
        worst_fn, worst_layers = load_funcs_data(os.path.join(run_path, f"{binary}_no_propagation.json"),
                                                 get_layers=True)

        task_gen_comp = self.progress.add_task(
            "[bold bright_yellow]Generating 4 comparisons", total=4
        )
        self.task_gen_comp = task_gen_comp

        predict_direct, predict_scored = self.generate_comparison(original_fn, original_layers, predicted_fn,
                                                                  predicted_layers)

        self.progress.advance(self.task_binary, advance=(1 / 4))

        best_direct, best_scored = self.generate_comparison(original_fn, original_layers, best_fn, predicted_layers)

        self.progress.advance(self.task_binary, advance=(1 / 4))

        worst_direct, worst_scored = self.generate_comparison(original_fn, original_layers, worst_fn, predicted_layers)

        self.progress.advance(self.task_binary, advance=(1 / 4))

        best_vs_predict_direct, best_vs_predict_scored = self.generate_comparison(best_fn, best_layers, predicted_fn,
                                                                                  predicted_layers)

        self.progress.advance(self.task_binary, advance=(1 / 4))
        self.progress.remove_task(task_gen_comp)

        self.insert_result(run_path, collect_layered_partial_scores(predict_scored, bucket_growth_factor),
                           "pred-layered")
        self.insert_result(run_path, collect_layered_partial_scores(best_scored, bucket_growth_factor), "best-layered")
        self.insert_result(run_path, collect_layered_partial_scores(worst_scored, bucket_growth_factor),
                           "worst-layered")
        self.insert_result(run_path, collect_layered_partial_scores(best_vs_predict_scored, bucket_growth_factor),
                           "best_vs_pred-layered")

        self.insert_result(run_path, collect_partial_scores(predict_scored), "pred")
        self.insert_result(run_path, collect_partial_scores(best_scored), "best")
        self.insert_result(run_path, collect_partial_scores(worst_scored), "worst")
        self.insert_result(run_path, collect_partial_scores(best_vs_predict_scored), "best_vs_pred")

        self.insert_result(run_path, {"original": {"score": 0, "count": len(original_fn)},
                                      "predicted": {"score": 0, "count": len(predicted_fn)}}, "total_count")

        save_to_json(predict_direct, os.path.join(run_path, f"{binary}_comp.json"))
        save_to_json(predict_scored, os.path.join(run_path, f"{binary}_scored.json"))
        save_to_csv(predict_direct, os.path.join(run_path, f"{binary}_comp.csv"))

        if self.save_all:
            save_to_json(best_direct, os.path.join(run_path, f"{binary}_best-comp.json"))
            save_to_json(worst_direct, os.path.join(run_path, f"{binary}_worst-comp.json"))
            save_to_json(worst_scored, os.path.join(run_path, f"{binary}_worst-scored.json"))
            save_to_json(best_scored, os.path.join(run_path, f"{binary}_best-scored.json"))
            save_to_json(best_vs_predict_direct, os.path.join(run_path, f"{binary}_best_vs_pred-comp.json"))
            save_to_json(best_vs_predict_scored, os.path.join(run_path, f"{binary}_best_vs_pred-scored.json"))

    def generate_comparison(self, original_fn, original_layers, predicted_fn, predicted_layers):
        # can have imprecisions at the 17th decimal place

        direct = collect_layered_pairs(original_fn, original_layers, predicted_fn, predicted_layers)
        scored = {layer_index: {} for layer_index, layer in direct.items()}
        total = sum(len(layer) for layer in direct.values())
        task_score = self.progress.add_task(f"[bold bright_yellow]Scoring {total} functions", total=total)

        if self.pool_size > 1:
            processed_pairs = 0
            scoring_args = []
            processes = []
            started = 0
            m = mp.Manager()
            result_queue = m.Queue()

            build_scoring_args(self.calculator, direct, original_fn, scoring_args)
            total = len(scoring_args)
            num_workers = min(self.pool_size, total)
            chunk_size = int(total / num_workers)
            last_chunk_size = total - chunk_size * (num_workers - 1)

            for i in range(0, num_workers):
                if i == num_workers - 1:
                    chunk_size = last_chunk_size
                p = mp.Process(target=score_parallel, args=(scoring_args[started:started + chunk_size], result_queue))
                processes.append(p)
                p.start()
                started += chunk_size

            while processed_pairs < total:
                try:
                    group, entrypoint, orig_name, pred_name, score = result_queue.get()
                    scored[group][entrypoint] = {"original": orig_name, "predicted": pred_name,
                                                 "score": score}
                    processed_pairs += 1
                    self.progress.advance(task_score)

                    if processed_pairs % 20 == 0:
                        self.progress.advance(self.task_gen_comp, advance=((20 / total)))

                except KeyboardInterrupt:
                    for p in processes:
                        p.terminate()
                    exit(0)
            self.progress.advance(self.task_gen_comp, advance=((total // 20) / total))
        else:
            for group, layer in direct.items():
                for orig_name, pred_name in layer.items():
                    entrypoint = find_entrypoint(original_fn, orig_name, pred_name)
                    score = self.calculator(orig_name, pred_name, entrypoint)
                    scored[group][entrypoint] = {"original": orig_name, "predicted": pred_name,
                                                 "score": score}
                    self.progress.advance(task_score)

        self.progress.remove_task(task_score)
        return direct, scored

    def insert_result(self, run_path, result, compare_type):
        model_name, source_dir_name, run, binary = split_run_path(run_path)
        # self.console.log(f"Inserting {result} for {compare_type} in {run_path}")
        self.results[model_name][source_dir_name][run][binary][compare_type] = result

    def get_median_results(self, model_name, source_dir_name, binary):
        scores = dict(self.results[model_name][source_dir_name][0][binary].copy())
        output = {}
        for group_name, group in scores.items():
            output[group_name] = {}
            for layer_name, layer in group.items():
                output[group_name][layer_name] = {"score": statistics.median(layer["scores"])}
                output[group_name][layer_name]["count"] = statistics.median(layer["counts"])
        return output

    def get_mean_results(self, model_name, source_dir, binary):
        return self.results[model_name][source_dir][0][binary]
