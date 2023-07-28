import argparse
from datetime import time

from rAIversing.AI_modules.openAI_core import chatGPT
from rAIversing.Engine import rAIverseEngine
from rAIversing.Ghidra_Custom_API import *

from rAIversing.evaluator.EvaluationManager import EvaluationManager
from rAIversing.evaluator.LayeredEvaluator import LayeredEvaluator
from rAIversing.evaluator.utils import make_run_path, layers_str_for_bucket
from rAIversing.pathing import *
from rAIversing.AI_modules.openAI_core.PromptEngine import PromptEngine
import json
from rAIversing.utils import *
from DataGather.src.DataGather import run_for_packages, create_sample_structure


def testbench(ai_module):
    pass


def evaluation(ai_module=None, parallel=1, bucketing=False, growth_factor=0.33, no_layering=False, runs=1):
    ai_modules = [ai_module]
    #ai_modules = [chatGPT.api_key(engine=PromptEngine.GPT_4)]
    source_dirs = [P2IM_BINS_ROOT,BINUTILS]

    eval_man = EvaluationManager(source_dirs, ai_modules, runs, connections=parallel)
    eval_man.run()

    if no_layering:
        eval_man.evaluate()
    else:
        eval_man.evaluate(LayeredEvaluator, growth_factor=growth_factor if bucketing else 0.0)


def run_on_ghidra_project(path, project_name=None, binary_name=None, ai_module=None, custom_headless_binary=None,
                          max_tokens=None, dry_run=False, parallel=1):
    if ai_module is None:
        raise ValueError("No AI module was provided")
    if not os.path.isdir(os.path.abspath(path)):
        if os.path.isdir(f"{os.path.join(PROJECTS_ROOT, path)}"):
            path = f"{os.path.join(PROJECTS_ROOT, path)}"
        else:
            print(f"Path {path} does not exist")
            return
    else:
        path = os.path.abspath(path)

    if binary_name is None:
        if project_name is None:
            binary_name = os.path.basename(path)
        else:
            binary_name = project_name
    if project_name is None:
        project_name = os.path.basename(path).split(".")[0]
    import_path = check_and_fix_project_path(path)
    if not is_already_exported(import_path, binary_name):
        existing_project_to_c_code(import_path, binary_name, project_name,
                                   custom_headless_binary=custom_headless_binary,
                                   max_cpu=parallel if parallel > 1 else 2)
    raie = rAIverseEngine(ai_module, json_path=f"{os.path.join(import_path, binary_name)}.json", max_tokens=max_tokens)
    if dry_run:
        raie.dry_run()
        return

    raie.max_parallel_functions = parallel
    raie.run_parallel_rev()

    raie.export_processed(all_functions=True)
    import_changes_to_existing_project(import_path, binary_name, project_name,
                                       custom_headless_binary=custom_headless_binary)


def run_on_new_binary(binary_path, language_id="", compiler_id="", ai_module=None, custom_headless_binary=None,
                      max_tokens=None, dry_run=False,
                      output_path=None, parallel=1, project_name=None):
    if ai_module is None:
        raise ValueError("No AI module was provided")
    import_path = check_and_fix_bin_path(binary_path)
    binary_to_c_code(import_path, language_id=language_id, compiler_id=compiler_id,
                     custom_headless_binary=custom_headless_binary, project_location=output_path,
                     project_name=project_name, max_cpu=parallel if parallel > 1 else 2)

    binary_name = os.path.basename(binary_path).replace(".", "_")
    project_name = binary_name if project_name is None else project_name
    if output_path:
        json_path = f"{os.path.join(output_path, binary_name)}.json"
        project_location = os.path.join(output_path, project_name)
    else:
        json_path = f"{os.path.join(PROJECTS_ROOT, binary_name, binary_name)}.json"
        project_location = os.path.join(PROJECTS_ROOT, binary_name)
    raie = rAIverseEngine(ai_module, json_path=json_path, binary_path=import_path, max_tokens=max_tokens)
    if dry_run:
        raie.dry_run()
        return
    raie.max_parallel_functions = parallel
    raie.run_parallel_rev()

    raie.export_processed(all_functions=True)
    import_changes_to_existing_project(project_location, binary_name, project_name,
                                       custom_headless_binary=custom_headless_binary)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='rAIversing', description='Reverse engineering tool using AI')
    parser.add_argument('--testbench', action='store_true', help='Run testbench')
    parser.add_argument('-a', '--api_key_path', help='OpenAI API key path (preferred)', default=None)
    parser.add_argument('-g', '--ghidra_path', help='/path/to/custom/ghidra/support/analyzeHeadless', default=None)
    parser.add_argument('-m', '--max_token', help='Max Tokens before Skipping Functions', default=None, type=int)
    parser.add_argument('-t', '--threads', help='Number of parallel requests', default=1, type=int)
    parser.add_argument('-d', '--dry', help='Dry run to calculate how many tokens will be used', action='store_true')
    parser.add_argument('-e', '--engine', help='Engine to use(gpt-3.5-turbo/gpt-4/hybrid)', default="gpt-3.5-turbo")
    subparsers = parser.add_subparsers(help='sub-command help', dest='command')

    ghidra_selection = subparsers.add_parser('ghidra', help='Run rAIversing on a ghidra project')
    binary_selection = subparsers.add_parser('binary', help='Run rAIversing on a new binary')
    evaluation_selection = subparsers.add_parser('evaluation', help='Run evaluation pipeline')

    evaluation_selection.add_argument('-b', '--bucketing',
                                      help='Use Layer bucketing for layered Evaluation (growth factor of 0.33 is default)',
                                      action='store_true')
    evaluation_selection.add_argument('-g', '--growth_factor',
                                      help='Growth factor for Layer bucketing. Default is 0.33', default=0.33,
                                      type=float)
    evaluation_selection.add_argument('--no_layering',
                                      help='Do not use Layering for Evaluation (Overrides bucketing and growth factor)',
                                      action='store_true')
    evaluation_selection.add_argument('-r', '--runs', help='Number of runs for Evaluation', default=1, type=int)

    ghidra_selection.add_argument('-p', '--path', help='/path/to/directory/containing/project.rep/', required=True)
    ghidra_selection.add_argument('-b', '--binary_name', help='name of the used binary', default=None)
    ghidra_selection.add_argument('-n', '--project_name', help='Project Name as entered in Ghidra', default=None)

    binary_selection.add_argument('-p', '--path',
                                  help=f'Location of the binary file either absolute or relative to {BINARIES_ROOT}',
                                  required=True)
    binary_selection.add_argument('-l', '--language_id',
                                  help='Language ID as defined in Ghidra (e.g.: x86:LE:64:default) Will be auto detected by Ghidra if not specified',
                                  default=None)
    binary_selection.add_argument('-c', '--compiler_id',
                                  help='Compiler ID as defined in Ghidra (e.g.: gcc) Will be auto detected by Ghidra if not specified',
                                  default=None)
    binary_selection.add_argument('-n', '--project_name',
                                  help='Project Name for the Ghidra Project (defaults to the binary name)',
                                  default=None)
    binary_selection.add_argument('-o', '--output_path',
                                  help='Output path for the project aka ~/projects/{my_binary|project_name (if specified)} ',
                                  default=None)

    args = parser.parse_args()

    engine = PromptEngine(args.engine)
    if args.api_key_path is not None:
        ai_module = chatGPT.api_key(args.api_key_path, engine=engine)
    else:
        ai_module = chatGPT.api_key(engine=engine)

    if args.testbench:
        testbench(ai_module)
    elif args.command == "evaluation":
        evaluation(ai_module, args.threads, bucketing=args.bucketing, growth_factor=args.growth_factor,
                   no_layering=args.no_layering, runs=args.runs)
    elif args.command == "ghidra":
        print(args)
        run_on_ghidra_project(args.path, args.project_name, args.binary_name, ai_module=ai_module,
                              custom_headless_binary=args.ghidra_path, max_tokens=args.max_token, parallel=args.threads,
                              dry_run=args.dry)

    elif args.command == "binary":
        if not (args.language_id and args.compiler_id):
            if args.language_id and args.compiler_id:
                print(
                    f"WARNING: Custom Language ID: {args.language_id} and Compiler ID: {args.compiler_id} will be used!\n"
                    f"         This might lead to unexpected results!\n"
                    f"         Please make sure that the binary was compiled with the specified compiler and language!")
                time.sleep(10)
            else:
                if args.language_id:
                    print(f"WARNING: ONLY Custom Language ID: {args.language_id} was specified!\n"
                          f"         This might lead to unexpected results!\n"
                          f"         Make sure that the headless Ghidra instance can detect the compilerID correctly or specify it manually!\n")
                    time.sleep(10)

                else:
                    print(f"WARNING: Custom Compiler ID: {args.compiler_id} was specified without a Language ID!\n"
                          f"         This is not supported by Ghidra!\n"
                          f"         Please specify a Language ID or let Ghidra detect it automatically!\n"
                          f"Exiting...")
                    exit(1)

        run_on_new_binary(args.path, language_id=args.language_id, compiler_id=args.compiler_id, ai_module=ai_module,
                          custom_headless_binary=args.ghidra_path,
                          max_tokens=args.max_token, dry_run=args.dry, output_path=args.output_path,
                          parallel=args.threads, project_name=args.project_name)

    else:
        parser.print_help()
        exit(0)
