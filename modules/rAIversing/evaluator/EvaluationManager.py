import shutil
import subprocess
import time
from pathlib import Path

from rich.progress import Progress, TimeElapsedColumn

from rAIversing.AI_modules import AiModuleInterface
from rAIversing.Engine import rAIverseEngine
from rAIversing.Ghidra_Custom_API import binary_to_c_code, existing_project_to_c_code, folder_processor
from rAIversing.evaluator.DefaultEvaluator import DefaultEvaluator
from rAIversing.evaluator.LayeredEvaluator import LayeredEvaluator
from rAIversing.evaluator.utils import make_run_path, check_extracted
from rAIversing.pathing import *
from rAIversing.utils import nondestructive_savefile_merge


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
            no_prop = json_path.name.endswith("no_propagation.json")
            raie = rAIverseEngine(ai_module, json_path=json_path)
            raie.max_parallel_functions = self.connections
            raie.run_parallel_rev(no_propagation=no_prop)

    def run(self):
        for ai_module in self.ai_modules:
            for source_dir in self.source_dirs:
                for run in range(1, self.runs + 1):
                    model_name = ai_module.get_model_name()
                    usable_binaries = os.listdir(os.path.join(source_dir, "stripped"))
                    for binary in usable_binaries:
                        if not check_extracted(model_name, source_dir, binary):
                            continue
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
        debug = True

        ##########################################################################################################
        with Progress(*Progress.get_default_columns(),TimeElapsedColumn(),transient=False) as progress:
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

                    bin_paths = list(Path(os.path.join(source_dir, "stripped")).rglob("*"))

                    try:
                        with open(os.path.join(project_location, "extraction_done"), "r") as f:
                            state = f.read()
                            if state == "done":
                                if debug:
                                    print(f"extraction for {model_name} and {source_dir_name} already done")
                                continue
                    except FileNotFoundError:
                        pass

                    #########################################################################################
                    task_import = progress.add_task(                                                        #
                        f"[bold bright_yellow]Importing {len(bin_paths) * 3} binaries/versions into Ghidra",#
                        total=(len(bin_paths) * 3))                                                         #
                    #########################################################################################

                    try:
                        cmd = folder_processor(source_dir,
                                               project_name=f"eval_{model_name}_{source_dir_name}",
                                               project_location=project_location,
                                               export_path=os.path.join(project_location),
                                               debug=debug, max_cpu=self.connections,import_only=True
                                               )
                        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        while True:
                            output = process.stdout.readline()
                            if process.poll() is not None:
                                break
                            if output:
                                if debug:
                                    print(output.strip().decode())
                                if "INFO  REPORT: Analysis succeeded for file:" in output.decode():
                                    progress.advance(task_import)

                    except KeyboardInterrupt:
                        exit(-1)
                    #############################################################################################
                    progress.remove_task(task_import)                                                           #
                    task_extraction = progress.add_task(                                                        #
                        f"[bold bright_yellow]Extracting {len(bin_paths) * 4} binaries/versions from Ghidra",   #
                        total=(len(bin_paths) * 4))                                                             #
                    #############################################################################################


                    try:
                        cmd = folder_processor(source_dir,
                                               project_name=f"eval_{model_name}_{source_dir_name}",
                                               project_location=project_location,
                                               export_path=os.path.join(project_location),
                                               debug=debug, max_cpu=self.connections, process_only=True
                                               )
                        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        while True:
                            output = process.stdout.readline()
                            if process.poll() is not None:
                                break
                            if output:
                                if debug:
                                    print(output.strip().decode())
                                if "#@#@#@#@#@#@#" in output.decode() or "rAIversing/modules/ghidra/ghidra_scripts/ExtractCcode.java (HeadlessAnalyzer)" in output.decode():
                                    progress.advance(task_extraction)

                    except KeyboardInterrupt:
                        exit(-1)
                    for binary_path in Path(os.path.join(source_dir, "original")).rglob("*"):
                        binary = os.path.basename(binary_path).replace("_original", "")
                        export_path = os.path.join(project_location, binary)
                        try:
                            time.sleep(1)
                            existing_project_to_c_code(project_location=project_location, binary_name=f"{binary}_original",
                                                       project_name=f"eval_{model_name}_{source_dir_name}",
                                                       export_with_stripped_names=True, export_path=export_path,
                                                       debug=debug,max_cpu=self.connections,folder_path="original"
                                                       )
                        except KeyboardInterrupt:
                            exit(-1)
                        progress.advance(task_extraction)

                    with open(os.path.join(project_location, "extraction_done"), "w") as f:
                        f.write("done")

                    #############################################################################
                    progress.remove_task(task_extraction)
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
                        if not check_extracted(model_name, source_dir, binary):
                            continue
                        for file in os.listdir(extraction_path):
                            if file.endswith(".json"):
                                if not os.path.exists(os.path.join(run_path, file)):
                                    shutil.copy(os.path.join(extraction_path, file), run_path)


    #TODO: Fix this
    def evaluate(self, evaluator=None,growth_factor=None):
        if evaluator is None:
            evaluator = self.evaluator
        else:
            self.evaluator = evaluator(self.ai_modules, self.source_dirs,
                                       self.runs, pool_size=self.connections)
        if growth_factor is not None:
            self.evaluator.evaluate(growth_factor=growth_factor)
        else:
            self.evaluator.evaluate()
