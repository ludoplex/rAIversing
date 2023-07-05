import shutil
from pathlib import Path

from rich.progress import Progress, TimeElapsedColumn

from rAIversing.AI_modules import AiModuleInterface
from rAIversing.Engine import rAIverseEngine
from rAIversing.Ghidra_Custom_API import binary_to_c_code, existing_project_to_c_code
from rAIversing.evaluator.DefaultEvaluator import DefaultEvaluator
from rAIversing.evaluator.utils import make_run_path
from rAIversing.pathing import *


# evaluates the model given paths to testfolders with each 3 subfolders (original, stripped, no_propagation)
# for each binary in each subfolder, the model is run and the results are saved in a csv file
# TODO
class EvaluationManager:

    def __init__(self, source_dirs, ai_modules, runs=1, connections=1, evaluator=None):
        self.source_dirs = [source_dirs] if isinstance(source_dirs, str) else source_dirs
        self.ai_modules = [ai_modules] if isinstance(ai_modules, AiModuleInterface) else ai_modules
        self.runs = runs
        self.connections = connections
        self.evaluator = evaluator(self.ai_modules, self.source_dirs, self.runs,
                                   pool_size=self.connections) if evaluator is not None else DefaultEvaluator(
            self.ai_modules,
            self.source_dirs,
            self.runs,
            pool_size=self.connections)
        self.setup_dirs()
        self.extract_code()
        self.prepare_runs()

    def run_atomic(self, ai_module, run_path, binary):
        for json_path in Path(run_path).glob("*.json"):
            if json_path.name == f"{binary}_original.json" or json_path.name.endswith(
                    "comp.json") or json_path.name.endswith("scored.json"):
                continue
            else:
                no_prop = json_path.name.endswith("no_propagation.json")
                raie = rAIverseEngine(ai_module, json_path=json_path)
                raie.load_save_file()
                raie.max_parallel_functions = self.connections
                raie.run_parallel_rev(no_propagation=no_prop)

    def run(self):
        for ai_module in self.ai_modules:
            for source_dir in self.source_dirs:
                for run in range(1, self.runs + 1):
                    model_name = ai_module.get_model_name()
                    usable_binaries = os.listdir(os.path.join(source_dir, "stripped"))
                    # usable_binaries = ["CNC"]  # TODO remove
                    for binary in usable_binaries:
                        run_path = make_run_path(model_name, source_dir, run, binary)
                        self.run_atomic(ai_module, run_path, binary)

    def setup(self):
        self.setup_dirs()
        self.extract_code()
        self.prepare_runs()

    def setup_dirs(self):
        for ai_module in self.ai_modules:
            model_name = ai_module.get_model_name()
            for source_dir in self.source_dirs:
                source_dir_name = os.path.basename(source_dir)
                for binary in os.listdir(os.path.join(source_dir, "stripped")):
                    os.makedirs(os.path.join(EVALUATION_ROOT, model_name, source_dir_name, "extraction", binary),
                                exist_ok=True)

                for run in range(0, self.runs + 1):
                    for binary in os.listdir(os.path.join(source_dir, "stripped")):
                        os.makedirs(make_run_path(model_name, source_dir, run, binary), exist_ok=True)
                        run_path = make_run_path(model_name, source_dir, run, binary)

    def extract_code(self):
        debug = False

        ##########################################################################################################
        with Progress(*Progress.get_default_columns(),TimeElapsedColumn(),transient=True) as progress:
            task_ai_modules = progress.add_task(f"[bold bright_yellow]Extracting for {len(self.ai_modules)} AI modules",
                                                total=len(self.ai_modules)) if len(self.ai_modules) > 1 else None
            ######################################################################################################

            for ai_module in self.ai_modules:
                model_name = ai_module.get_model_name()

                ########################################################################################
                task_source_dirs = progress.add_task(                                                  #
                    f"[bold bright_yellow]Extracting for {len(self.source_dirs)} source directories",  #
                    total=len(self.source_dirs)) if len(self.source_dirs) > 1 else None                #
                ########################################################################################

                for source_dir in self.source_dirs:
                    source_dir_name = os.path.basename(source_dir)
                    project_location = os.path.join(EVALUATION_ROOT, model_name, source_dir_name, "extraction")
                    try:
                        with open(os.path.join(source_dir, "proc_id"), "r") as f:
                            proc_id = f.read()
                    except FileNotFoundError:
                        print(f"proc_id file not found {os.path.join(source_dir, 'proc_id')} EXITING NOW!!! PLEASE ADD IT AND RESTART")
                        exit(-1)
                    bin_paths = list(Path(os.path.join(source_dir, "stripped")).rglob("*"))

                    #####################################################################################
                    task_extraction = progress.add_task(                                                #
                        f"[bold bright_yellow]Extracting {len(bin_paths) * 3} binaries/versions",       #
                        total=(len(bin_paths) * 3))                                                     #
                    #####################################################################################

                    for binary_path in bin_paths:
                        binary = os.path.basename(binary_path)
                        binary_to_c_code(binary_path, processor_id=proc_id,
                                         project_name=f"eval_{model_name}_{source_dir_name}",
                                         project_location=project_location,
                                         export_path=os.path.join(project_location, binary), debug=debug)

                        ######################################################################
                        progress.advance(task_extraction)                                    #
                    ##########################################################################

                    for binary_path in Path(os.path.join(source_dir, "original")).rglob("*"):
                        binary = os.path.basename(binary_path).replace("_original", "")
                        export_path = os.path.join(project_location, binary)
                        binary_to_c_code(binary_path, processor_id=proc_id,
                                         project_name=f"eval_{model_name}_{source_dir_name}",
                                         project_location=project_location, export_path=export_path, debug=debug)
                        existing_project_to_c_code(project_location=project_location, binary_name=f"{binary}_original",
                                                   project_name=f"eval_{model_name}_{source_dir_name}",
                                                   export_with_stripped_names=True, export_path=export_path,
                                                   debug=debug)

                        ########################################################################
                        progress.advance(task_extraction)                                      #
                    ############################################################################

                    for binary_path in Path(os.path.join(source_dir, "no_propagation")).rglob("*"):
                        binary = os.path.basename(binary_path).replace("_no_propagation", "")
                        export_path = os.path.join(project_location, binary)
                        binary_to_c_code(binary_path, processor_id=proc_id,
                                         project_name=f"eval_{model_name}_{source_dir_name}",
                                         project_location=project_location, export_path=export_path)

                        #########################################################################
                        progress.advance(task_extraction)                                       #
                    progress.remove_task(task_extraction)                                       #
                    progress.advance(task_source_dirs) if len(self.source_dirs) > 1 else None   #
                progress.remove_task(task_source_dirs) if len(self.source_dirs) > 1 else None   #
                progress.advance(task_ai_modules) if len(self.ai_modules) > 1 else None         #
            progress.remove_task(task_ai_modules) if len(self.ai_modules) > 1 else None         #
            progress.stop()                                                                     #
            #####################################################################################

    def prepare_runs(self):
        for ai_module in self.ai_modules:
            model_name = ai_module.get_model_name()
            for source_dir in self.source_dirs:
                for run in range(1, self.runs + 1):
                    for binary_path in Path(os.path.join(source_dir, "stripped")).rglob("*"):
                        binary = os.path.basename(binary_path)
                        extraction_path = os.path.join(EVALUATION_ROOT, model_name, os.path.basename(source_dir),
                                                       "extraction", binary)
                        run_path = make_run_path(model_name, source_dir, run, binary)

                        for file in os.listdir(extraction_path):
                            if file.endswith(".json"):
                                if not os.path.exists(os.path.join(run_path, file)):
                                    shutil.copy(os.path.join(extraction_path, file), run_path)

    def evaluate(self, evaluator=None):
        if evaluator is None:
            evaluator = self.evaluator
        else:
            self.evaluator = evaluator(self.ai_modules, self.source_dirs,
                                       self.runs, pool_size=self.connections)
        self.evaluator.evaluate()
