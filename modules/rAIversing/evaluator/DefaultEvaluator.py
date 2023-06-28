import statistics

from rich.console import Console, CONSOLE_SVG_FORMAT
from rich.table import Table, Column
from rAIversing.evaluator.EvaluatorInterface import EvaluatorInterface
from rAIversing.evaluator.ScoringAlgos import calc_score
from rAIversing.evaluator.utils import *
from rAIversing.evaluator import load_funcs_data
from rAIversing.evaluator.utils import setup_results, create_table, build_scoring_args, score_parallel, \
    calc_relative_percentage_difference, fill_table
from rAIversing.utils import save_to_json
import multiprocessing as mp
from rich.progress import Progress

class DefaultEvaluator(EvaluatorInterface):
    def __init__(self, ai_modules, source_dirs, runs=1, calculation_function=calc_score,pool_size=1):
        super().__init__(ai_modules, source_dirs, runs, pool_size)
        self.task_binary = None
        self.calculator = calculation_function
        self.results = {}
        self.save_all = True
        self.console = Console(soft_wrap=True)
        self.progress = None
        setup_results(self.ai_modules, self.results, self.source_dirs, self.runs)

    def set_calculator(self, calculation_function):
        self.calculator = calculation_function

    def evaluate(self):

        with Progress(transient=True) as progress:
            task_ai_modules = progress.add_task(f"[bold bright_yellow]Evaluating {len(self.ai_modules)} AI modules", total=len(self.ai_modules))

            self.progress = progress

            for ai_module in self.ai_modules:
                model_name = ai_module.get_model_name()

                task_source_dirs = progress.add_task(f"[bold bright_yellow]Evaluating {len(self.source_dirs)} source directories", total=len(self.source_dirs))

                for source_dir in self.source_dirs:
                    source_dir_name = os.path.basename(source_dir)
                    task_runs = progress.add_task(f"[bold bright_yellow]Evaluating {self.runs} runs", total=self.runs)
                    for run in range(1, self.runs + 1):
                        usable_binaries = os.listdir(os.path.join(source_dir, "stripped"))

                        task_binary = progress.add_task(f"[bold bright_yellow]Evaluating {len(usable_binaries)} binaries", total=len(usable_binaries))
                        self.task_binary = task_binary

                        for binary in usable_binaries:
                            self.evaluate_atomic(make_run_path(model_name, source_dir_name, run, binary), binary)

                            progress.advance(task_runs, advance=(1/len(usable_binaries)))
                        progress.remove_task(task_binary)
                        progress.advance(task_source_dirs, advance=(1/self.runs))
                    progress.remove_task(task_runs)
                    progress.advance(task_ai_modules, advance=(1/len(self.source_dirs)))
                progress.remove_task(task_source_dirs)
            progress.stop()

            self.collect_cumulative_results()
            self.display_results()

    def evaluate_atomic(self, run_path, binary):

        predicted_fn = load_funcs_data(os.path.join(run_path, f"{binary}.json"))
        original_fn = load_funcs_data(os.path.join(run_path, f"{binary}_original.json"))
        best_fn = load_funcs_data(os.path.join(run_path, f"{binary}_original_stripped.json"))
        worst_fn = load_funcs_data(os.path.join(run_path, f"{binary}_no_propagation.json"))

        task_gen_comp = self.progress.add_task(f"[bold bright_yellow]Generating 4 comparisons", total=4)
        self.task_gen_comp = task_gen_comp

        predict_direct, predict_scored = self.generate_comparison(original_fn, predicted_fn)

        #self.progress.advance(task_gen_comp)
        self.progress.advance(self.task_binary,advance=(1/4))

        best_direct, best_scored = self.generate_comparison(original_fn, best_fn)

        #self.progress.advance(task_gen_comp)
        self.progress.advance(self.task_binary,advance=(1/4))

        worst_direct, worst_scored = self.generate_comparison(original_fn, worst_fn)

        #self.progress.advance(task_gen_comp)
        self.progress.advance(self.task_binary,advance=(1/4))

        best_vs_predict_direct, best_vs_predict_scored = self.generate_comparison(best_fn, predicted_fn)

        #self.progress.advance(task_gen_comp)
        self.progress.advance(self.task_binary,advance=(1/4))
        self.progress.remove_task(task_gen_comp)


        self.insert_result(run_path, collect_partial_scores(predict_scored), "pred")
        self.insert_result(run_path, collect_partial_scores(best_scored), "best")
        self.insert_result(run_path, collect_partial_scores(worst_scored), "worst")
        self.insert_result(run_path, collect_partial_scores(best_vs_predict_scored), "best_vs_pred")

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
        total = 0
        for layer in direct.values():
            total += len(layer)
        task_score = self.progress.add_task(f"[bold bright_yellow]Scoring {total} functions", total=total)

        if self.pool_size >1 and True:
            processed_pairs = 0
            scoring_args = []
            processes = []
            started = 0
            m = mp.Manager()
            result_queue = m.Queue()

            build_scoring_args(self.calculator,direct,original,scoring_args)
            total = len(scoring_args)
            num_workers = min(self.pool_size,total)
            chunk_size = int(total/num_workers)
            last_chunk_size = total - chunk_size*(num_workers-1)

            for i in range(0,num_workers):
                if i == num_workers-1:
                    chunk_size = last_chunk_size
                p = mp.Process(target=score_parallel,args=(scoring_args[started:started+chunk_size],result_queue))
                processes.append(p)
                p.start()
                started += chunk_size

            while processed_pairs < total:
                try:
                    group,entrypoint,orig_name,pred_name,score = result_queue.get()
                    scored[group][entrypoint] = {"original": orig_name, "predicted": pred_name,
                                                "score": score}
                    processed_pairs += 1
                    self.progress.advance(task_score)

                    if processed_pairs % 20 == 0:
                        self.progress.advance(self.task_gen_comp,advance=((20/total)))

                except KeyboardInterrupt:
                    for p in processes:
                        p.terminate()
                    exit(0)
            self.progress.advance(self.task_gen_comp,advance=((total//20)/total))
            self.progress.remove_task(task_score)
            return direct, scored
        else:
            for group, layer in direct.items():
                for orig_name, pred_name in layer.items():
                    entrypoint = find_entrypoint(original, orig_name, pred_name)
                    score = self.calculator(orig_name, pred_name, entrypoint)
                    scored[group][entrypoint] = {"original": orig_name, "predicted": pred_name,
                                                 "score": score}
                    self.progress.advance(task_score)
            self.progress.remove_task(task_score)
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
            table = create_table(f"{model_name} on {source_dir_name} (Run {run})")
            for binary in usable_binaries:
                scores = self.get_results(model_name, source_dir_name, run, binary)
                fill_table(table, scores, binary)
            export_console = Console(record=True, width=160)
            export_console.print(table)
            run_path = make_run_path(model_name, source_dir, run, "")
            export_console.save_svg(os.path.join(run_path, f"Eval_{model_name}_{source_dir_name}_run_{run}.svg"),
                                    clear=False, title="",
                                    code_format=CONSOLE_SVG_FORMAT.replace("{chrome}", ""))

    def create_average_results(self, model_name, source_dir):
        source_dir_name = os.path.basename(source_dir)
        table = create_table(f"Average {model_name} on {source_dir_name} ({self.runs} runs)")
        usable_binaries = os.listdir(os.path.join(source_dir, "stripped"))
        for binary in usable_binaries:
            scores = self.get_average_results(model_name, source_dir_name, binary)
            fill_table(table, scores, binary)
        export_console = Console(record=True, width=165)
        export_console.print(table)
        export_path = make_run_path(model_name, source_dir, "0", "")
        export_console.save_svg(
            os.path.join(export_path, f"Eval_Avg_{model_name}_{source_dir_name}_{self.runs}_runs.svg"), clear=False,
            title="",
            code_format=CONSOLE_SVG_FORMAT.replace("{chrome}", ""))

    def create_median_results(self, model_name, source_dir):
        source_dir_name = os.path.basename(source_dir)
        table = create_table(f"Median {model_name} on {source_dir_name} ({self.runs} runs)")
        usable_binaries = os.listdir(os.path.join(source_dir, "stripped"))
        for binary in usable_binaries:
            scores = self.get_median_results(model_name, source_dir_name, binary)

            fill_table(table, scores, binary)
        export_console = Console(record=True, width=165)
        export_console.print(table)
        export_path = make_run_path(model_name, source_dir, "0", "")
        export_console.save_svg(
            os.path.join(export_path, f"Eval_Median_{model_name}_{source_dir_name}_{self.runs}_runs.svg"), clear=False,
            title="",
            code_format=CONSOLE_SVG_FORMAT.replace("{chrome}", ""))


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

