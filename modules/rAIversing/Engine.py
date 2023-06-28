import json
import logging
import os, re

import multiprocessing as mp
import threading
import time

from rich.console import Console

from rAIversing.AI_modules import AiModuleInterface
from rAIversing.AI_modules.openAI_core import chatGPT
from rAIversing.pathing import PROJECTS_ROOT
from rAIversing.utils import check_and_fix_bin_path, extract_function_name, generate_function_name, MaxTriesExceeded, \
    check_and_fix_double_function_renaming, check_do_nothing, get_random_string, ptr_escape, prompt_parallel, \
    handle_spawn_worker, locator, to_snake_case


class rAIverseEngine:
    def __init__(self, ai_module, json_path="", binary_path="", max_tokens=None):
        self.max_parallel_functions = os.cpu_count() // 2
        self.max_tokens = max_tokens if max_tokens is not None else ai_module.get_max_tokens()
        self.ai_module = ai_module  # type: chatGPT
        self.functions = {}
        self.used_tokens = 0
        self.layers = []
        self.current_fn_lookup = {}
        self.original_fn_lookup = {}
        self.locked_functions = []
        self.to_be_redone = []
        self.logger = logging.getLogger("rAIverseEngine")
        self.logger.setLevel(logging.DEBUG)
        self.binary_name = os.path.basename(binary_path).replace(".", "_")
        self.path_to_save_file = json_path if json_path != "" else f"{PROJECTS_ROOT}/{self.binary_name}/{self.binary_name}.json"
        self.skip_failed_functions = True  # TODO make this a parameter
        self.retries = 5  # TODO make this a parameter
        logging.basicConfig()
        self.console = Console(soft_wrap=True)

    def load_save_file(self):
        self.console.log(f"[bold green_yellow]Loading Data from {self.path_to_save_file}[/bold green_yellow]")
        if os.path.isfile(self.path_to_save_file):
            with open(self.path_to_save_file) as f:
                save_file = json.load(f)
        elif os.path.isfile(os.path.join(f"{PROJECTS_ROOT}", self.path_to_save_file)):
            self.path_to_save_file = os.path.join(f"{PROJECTS_ROOT}", self.path_to_save_file)
            with open(self.path_to_save_file) as f:
                save_file = json.load(f)
        else:
            self.console.print(f"[bold red]No functions.json found[/bold red]")
            raise Exception(f"Path to functions.json not found: {self.path_to_save_file}")

        if "functions" in save_file.keys():
            self.functions = save_file["functions"]
            self.used_tokens = save_file["used_tokens"]
            self.layers = save_file["layers"]
            self.locked_functions = save_file["locked_functions"]
        else:
            self.functions = save_file

        for name, data in self.functions.items():
            current_name = data["current_name"] if "current_name" in data.keys() else name
            self.functions[name]["current_name"] = current_name
            self.current_fn_lookup[name] = current_name
            self.original_fn_lookup[current_name] = name

    def save_functions(self):
        with open(self.path_to_save_file, "w") as f:
            save_file = {"functions": self.functions, "used_tokens": self.used_tokens, "layers": self.layers,
                         "locked_functions": self.locked_functions}
            json.dump(save_file, f, indent=4)

    def is_import_needed(self):
        for name, data in self.functions.items():
            if data["imported"] == False and not data["skipped"]:
                return True
        return False

    def get_lowest_function_layer(self):
        lflList = []
        for name, data in self.functions.items():
            if data["improved"] == False and not data["skipped"]:
                escaped_code = ptr_escape(data["code"])
                if len(escaped_code.split("FUN_")) == 2 or "called" not in data.keys() or len(data["called"]) == 0:
                    lflList.append(name)
        if len(lflList) == 0:
            missing = self.get_missing_functions()
            for name in missing:
                data = self.functions[name]
                escaped_code = ptr_escape(data["code"])
                if len(escaped_code.split(name)) == len(escaped_code.split("FUN_")):
                    lflList.append(name)

        if len(lflList) == 0:
            sorted_missing = self.get_sorted_missing()
            if len(sorted_missing) > 1:
                self.logger.info(f'{len(sorted_missing)} functions missing, locking {sorted_missing[0]}')
                lock_candidate = sorted_missing.pop(0)
                self.lock_function(lock_candidate)
                lflList = self.get_lowest_function_layer()
                if len(lflList) != 0:
                    if lflList not in self.to_be_redone:
                        self.to_be_redone.append(lflList)
                        for name in lflList:
                            self.functions[name]["code_backup"] = self.functions[name]["code"]
                    # print(lflList)
                    self.logger.info(f"Locked functions: {self.locked_functions}")
        if len(lflList) == 0:
            missing = self.get_missing_functions()
            regex = r"FUN_\w+"
            for name in missing:  # Probably just one entry
                print(name)
                pass

        return lflList

    def get_sorted_missing(self):
        """
        Returns a list of missing functions sorted by the amount of missing functions calling them.
        :return:
        """
        missing = self.get_missing_functions()
        sorted_missing = sorted(missing,
                                key=lambda k: len(list(set(self.functions[k]['called']).intersection(missing))),
                                reverse=False)
        sorted_missing = sorted(sorted_missing,
                                key=lambda k: len(list(set(self.functions[k]['calling']).intersection(missing))),
                                reverse=True)
        return sorted_missing

    def skip_function(self, name):
        new_name = f"{name.replace('FUN_', 'FUNC_')}"
        renaming_dict = {name: new_name}
        improved_code = self.functions[name]["code"].replace(name, new_name)
        self.functions[name]["skipped"] = True
        self.functions[name]["code"] = improved_code
        self.functions[name]["current_name"] = new_name
        self.functions[name]["renaming"] = renaming_dict
        self.rename_for_all_functions(renaming_dict)

    def lock_function(self, name):
        self.logger.info(f"Locking function {name}")
        self.skip_function(name)
        self.locked_functions.append(name)

    def handle_unlocking(self):
        if len(self.locked_functions) > 0:
            for name in self.locked_functions:
                self.unlock_function(name)
            self.locked_functions = []

    def unlock_function(self, name):
        old_name = name.replace('FUN_', 'FUNC_')
        renaming_dict = {old_name: name}
        improved_code = self.functions[name]["code"].replace(old_name, name)
        self.functions[name]["skipped"] = False
        self.functions[name]["code"] = improved_code
        self.functions[name]["current_name"] = name
        self.functions[name]["renaming"] = renaming_dict
        self.locked_functions.remove(name)
        self.rename_for_all_functions(renaming_dict, overwrite=True)

    def get_missing_functions(self):
        missing = []
        for name, data in self.functions.items():
            if not data["improved"] and not data["skipped"]:
                missing.append(name)
        return missing

    def fix_function_name(self, code, rename_dict, function_name):
        if function_name not in code:
            if function_name in rename_dict.keys():
                new_name = f"{rename_dict[function_name]}_{function_name.replace('FUN_', '')}"
                self.functions[function_name]["current_name"] = new_name
                code.replace(rename_dict[function_name], new_name)

    def rename_for_all_functions(self, renaming_dict, overwrite=False):
        for name, data in self.functions.items():
            for old, new in renaming_dict.items():
                if old == new:
                    continue
                if old == "" or new == "":
                    # self.logger.error(f"Empty string in renaming dict: >{old}< -> >{new}<")
                    continue
                try:
                    val = hex(int(old, 16))
                    continue
                except:
                    pass
                if "[" in old or "(" in old or "{" in old:
                    continue
                if "Var" in old or "param" in old or "local" in old or "PTR" in old or "DAT" in old or "undefined" in old:
                    continue

                if "FUN_" in new and not overwrite:
                    # self.logger.warning(f"Skipping renaming of {old} to {new}")
                    continue
                if not "FUN_" in old and not overwrite:  # Currently just renaming functions but i already have the "hooks" for pointers
                    continue
                data["code"] = data["code"].replace(old, new)

    def undo_bad_renaming(self, renaming_dict, code, original_code):
        """This function is used to undo bad renaming of functions that are not called by other hidden functions.
        As there are no guarantees that the Ai module won't rename already renamed functions we check if the old name,
        is known as a current name of a function. If it is we undo the renaming by the following steps:
        1. we sort the renaming dict by the length of the new name
            This way we can undo the renaming of the longest names first and avoid renaming of already renamed functions
        2. We replace the new name with a random string that is not used in the code and therefore won't be overwritten
        3. We replace the random string with the old name

        If multiple functions are renamed to the same name we can rely on the fact that the sorting is stable,
        and the entries with the same length will be sorted by the order they were added to the dict which is the order
        in wich they occurred in the code(Just AI things).
        """

        current_names = self.current_fn_lookup.values()
        new_names = list(renaming_dict.values())
        old_names = list(renaming_dict.keys())
        to_be_handled_duplicates = []
        temporary_remapping = {}
        for old, new in renaming_dict.items():
            if "FUN_" in old:
                name = old
        renaming_dict_sorted = dict(sorted(renaming_dict.items(), key=lambda item: (-len(item[1]), item[1])))
        # print("")
        # print(renaming_dict_sorted)
        # print("")
        for old, new in renaming_dict_sorted.items():
            if new == "" or old == "":
                continue

            if "FUN_" in old:
                name = old
            if "PTR" in old or "DAT" in old:
                code = code.replace(new, old)
            if check_do_nothing(code) and "FUN_" in old:
                if "nothing" not in new.lower():
                    code = code.replace(new, "do_nothing")
                    print(f"Replaced {new} with do_nothing in {old}")
            elif "FUN_" in old and ("reverse" in new and "engineer" in new.lower()):
                print(f"not replacing reverse engineer in {old}")
                print(code)
            if old in current_names and "FUN_" not in old and old not in code:
                # self.logger.warning(f"(Currently not)Reversing potential false renaming of {old} to {new} in {self.get_original_name(old)}")
                # print(new)
                rand_str = get_random_string(10)
                temporary_remapping[rand_str] = old
                if new_names.count(new) > 1:
                    code = code.replace(new, rand_str,
                                        1)  # self.logger.warning(f"Multiple old names for {new} in {name}")
                else:
                    code = code.replace(new, rand_str)
                    continue

        for temp, intended in temporary_remapping.items():
            code = code.replace(temp, intended)

        return code

    def check_all_improved(self):
        for name, data in self.functions.items():
            if not data["improved"]:
                return False
        return True

    def count_processed(self):
        count = 0
        for name, data in self.functions.items():
            if data["improved"] == True or data["skipped"] == True:
                count += 1
        return count

    def run_parallel_rev(self, no_propagation=False):
        function_layer = len(self.layers) + 1
        skipped_remaining_functions = False
        self.skip_too_big()
        self.skip_do_nothing()
        overall_processed_functions = self.count_processed()
        lfl = []

        while not self.check_all_improved():
            self.console.log(f"[bold yellow]Gathering functions for layer [/bold yellow]{function_layer}")
            self.handle_unlocking()

            lfl = self.get_lowest_function_layer() if not no_propagation else self.get_missing_functions()
            if len(lfl) == 0:
                if len(self.get_missing_functions()) == 0:
                    self.console.log("[bold blue]All functions improved[/bold blue]")
                else:
                    self.console.print(f"[bold orange3]No functions found for layer [/bold orange3]{function_layer}")
                    self.console.print(f"These functions remain {self.get_missing_functions()}")
                break
            else:
                if len(self.layers) > 0:
                    old_layer = self.layers[-1]
                    leftover_functions = list(set(old_layer).intersection(set(lfl)))
                    if len(leftover_functions) == 0:
                        self.layers.append(lfl)
                    else:
                        lfl = leftover_functions
                else:
                    self.layers.append(lfl)

            function_layer = len(self.layers)
            self.console.print(
                f"Starting layer {function_layer} with {len(lfl)} of {len(self.functions)} functions. Overall processed functions: {overall_processed_functions}/{len(self.functions)} Used tokens: {self.used_tokens}")

            function_layer += 1
            processed_functions = 0
            started = 0
            prompting_args = []
            processes = []

            m = mp.Manager()
            result_queue = m.Queue()

            self.build_prompting_args(lfl, prompting_args, result_queue)
            total = len(prompting_args)

            for i in range(0, min(total, self.max_parallel_functions)):
                p = mp.Process(target=prompt_parallel, args=prompting_args.pop(0))
                p.start()
                processes.append(p)
                started += 1

            while processed_functions < total:
                try:
                    name, result = result_queue.get()
                    processed_functions += 1
                    if result == "SKIP":
                        self.skip_function(name)
                        handle_spawn_worker(processes, prompting_args, started)
                        continue
                    elif result == "EXIT":
                        self.console.print("Exiting... HardLimit reached")
                        exit(-1)
                    else:
                        current_cost = self.handle_result_processing(name, result, no_propagation=no_propagation)
                        self.used_tokens += current_cost

                    renaming_dict = result[1]
                    self.console.print(
                        f"{processed_functions}/{total} | ({self.used_tokens}|{current_cost}) | [blue]{name}[/blue] -> [blue]{renaming_dict[name]}[/blue]")

                    # self.console.print(
                    #   f"{processed_functions}/{total} | Improved function [blue]{name}[/blue] for {current_cost} Tokens | Used tokens: {self.used_tokens}")

                    if processed_functions % 5 == 0:
                        self.save_functions()
                        self.console.print(f"{processed_functions}/{total} | Saved functions!")
                    time.sleep(1.5)
                    handle_spawn_worker(processes, prompting_args, started)
                except KeyboardInterrupt:
                    self.console.print(f"[bold red] \nKeyboard interrupt. Saving functions and exiting")
                    self.save_functions()
                    for p in processes:
                        p.terminate()
                    exit(0)
                except Exception as e:
                    self.console.print(f"Exception occured: {e}")
                    self.console.print(f"Saving functions")
                    self.save_functions()
                    self.console.print(f"{processed_functions}/{total} | Saved functions! Exiting!")
                    exit(0)

            for p in processes:
                p.join()
            self.save_functions()
            self.console.print(f"{processed_functions}/{total} | Saved functions!")
            overall_processed_functions += processed_functions
        self.save_functions()

    def skip_too_big(self):
        missing = self.get_missing_functions()
        for name in self.get_missing_functions():
            current_cost = self.ai_module.calc_used_tokens(self.ai_module.assemble_prompt(self.functions[name]["code"]))
            if current_cost > self.max_tokens:
                self.console.print(f"Function [blue]{name}[/blue] is too big [red]{current_cost}[/red] Skipping")
                self.skip_function(name)

    def build_prompting_args(self, lfl, prompting_args, result_queue):
        for name in lfl:

            current_cost = self.ai_module.calc_used_tokens(self.ai_module.assemble_prompt(self.functions[name]["code"]))
            if current_cost > self.max_tokens:
                self.console.print(f"Function [blue]{name}[/blue] is too big [red]{current_cost}[/red] Skipping")
                self.skip_function(name)
            else:
                prompting_args.append(
                    (self.ai_module, result_queue, name, str(self.functions[name]["code"]), self.retries))

    def handle_result_processing(self, name, result, no_propagation=False):
        try:
            improved_code = result[0]
            renaming_dict = result[1]
            total_tokens_used = result[2]
            to_be_improved_code = self.functions[name]["code"]
            improved_code = self.undo_bad_renaming(renaming_dict, improved_code, to_be_improved_code)
            improved_code = check_and_fix_double_function_renaming(improved_code, renaming_dict, name)
            improved_code, new_name = generate_function_name(improved_code, name)
            new_name = to_snake_case(new_name)
            renaming_dict[name] = new_name

        except Exception as e:
            self.console.print(f"[bold red]Error while improving {name} {e}[/bold red]" + locator())
            raise e

        self.functions[name]["improved"] = True
        self.functions[name]["code"] = improved_code
        self.functions[name]["current_name"] = new_name
        self.functions[name]["renaming"] = renaming_dict
        if not no_propagation:
            self.rename_for_all_functions(renaming_dict)
        return total_tokens_used

    def export_processed(self, all_functions=False, output_file=""):
        if output_file == "":
            output_file = self.path_to_save_file.rsplit(".", 1)[0] + "_processed.c"
        with open(output_file, 'w') as f:
            for name, data in self.functions.items():
                if data["improved"] or all_functions:
                    f.write(f'\n// {name} {data["entrypoint"]}\n')
                    f.write(data["code"].replace("\\\\", "\\").replace("\\n", "\n"))

    def get_current_name(self, function_name):
        return self.current_fn_lookup[function_name]

    def get_original_name(self, current_name):
        try:
            return self.original_fn_lookup[current_name]
        except KeyError:
            print(f"KeyError: {current_name} not found in Lookup")

    def update_current_name(self, function_name, current_name):
        old_current_name = self.current_fn_lookup[function_name]
        self.current_fn_lookup[function_name] = current_name
        self.original_fn_lookup[current_name] = function_name
        del self.original_fn_lookup[old_current_name]

    def dry_run(self):
        number_of_tokens = 0
        for name, data in self.functions.items():
            tokens = self.ai_module.calc_used_tokens(self.ai_module.assemble_prompt(data["code"]))
            if not tokens > self.max_tokens:
                number_of_tokens += tokens
        self.console.log(f"Number of tokens: {number_of_tokens} for {len(self.functions)} functions")

    def skip_do_nothing(self):
        renaming_dict = {}
        for name, data in self.functions.items():
            if check_do_nothing(data["code"]) and not data["improved"] and not data["skipped"]:
                self.skip_function(name)
