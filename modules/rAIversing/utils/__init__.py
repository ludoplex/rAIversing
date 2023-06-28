import csv
import json
import multiprocessing as mp
import random
import re
import string
from inspect import getframeinfo, stack

from rAIversing.pathing import *


class MaxTriesExceeded(Exception):
    """Raised when the max tries is exceeded"""


class OutOfTriesException(Exception):
    """Raised when the max tries is exceeded with an api error. Is your HardLimit reached?"""


class NoResponseException(Exception):
    """Raised when no response is received"""


class InvalidResponseException(Exception):
    """Raised when the response is invalid"""


class IncompleteResponseException(Exception):
    """Raised when the response is incomplete"""


def ptr_escape(string):
    rand_str = get_random_string(5)
    return string.replace("PTR_FUN_", rand_str)


def check_and_fix_bin_path(binary_path):
    if os.path.isfile(os.path.abspath(binary_path)):
        return os.path.abspath(binary_path)
    else:
        if os.path.isfile(os.path.join(BINARIES_ROOT, binary_path)):
            return os.path.join(BINARIES_ROOT, binary_path)
        else:
            raise FileNotFoundError(f"Binary {binary_path} not found in {BINARIES_ROOT}")


def check_and_fix_project_path(project_path):
    if os.path.isdir(os.path.abspath(project_path)):
        return os.path.abspath(project_path)
    else:
        if os.path.isdir(os.path.join(PROJECTS_ROOT, project_path)):
            return os.path.join(PROJECTS_ROOT, project_path)
        else:
            raise NotADirectoryError(f"Project {project_path} not found in {PROJECTS_ROOT}")


def check_and_create_project_path(project_path):
    if not os.path.isdir(project_path):
        os.mkdir(project_path)


def extract_function_name(code):
    if "WARNING: Removing unreachable block (ram," in code:
        code = code.split("\n\n")[1].split("(")[0].split("\n")[-1].split(" ")[-1]
        return code

    code = code.split("(")[0].split(" ")[-1]
    code = code.replace("\\n", "\n")

    splitted = re.split('[^a-zA-Z0-9_]', code)

    return splitted[-1]


def generate_function_name(code, name):
    new_name = f"{extract_function_name(code).replace('FUN_', '')}_{name.replace('FUN_', '')}"
    return code.replace(extract_function_name(code), new_name), new_name


def check_reverse_engineer_fail_happend(code):
    # returns true if the code contains reverse and engineer (in the case that the model called it reverse_engineered_function)
    code = extract_function_name(code)
    if "reverse" in code.lower() and "engineer" in code.lower():
        return True
    elif "improve" in code.lower() and "function" in code.lower():
        return True
    else:
        return False


def check_and_fix_double_function_renaming(code, renaming_dict, name):
    if name in renaming_dict.keys():
        present_name = extract_function_name(code)
        if present_name != renaming_dict[name]:
            if present_name not in renaming_dict[name]:
                # print(f"Replacing {present_name} with {renaming_dict[name]} in {name}")
                pass
            code = code.replace(present_name, renaming_dict[name])
    return code


def is_already_exported(project_location, binary_name):
    if os.path.isfile(os.path.join(project_location, f"{binary_name.replace('.', '_')}.json")):
        return True
    else:
        # print(f"""File {os.path.join(project_location, f'{binary_name.replace(".", "_")}.json')} not found""")
        return False


def get_random_string(length):
    # choose from all lowercase letter
    letters = string.ascii_uppercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str


def check_do_nothing(code):
    code = "{" + code.split("{")[1].split("}")[0] + "}"
    code = code.replace(" ", "").replace("\n", "").rstrip().strip()
    if "{return;}" == code:
        return True
    else:
        return False


def clear_extra_data(response, error):
    # Extra data: line 8 column 1 (char 177)
    # remove everything after char 177 from response
    last_del = 0
    e = str(error)
    while last_del != int(e.split("char ")[1].split(")")[0]):
        last_del = int(e.split("char ")[1].split(")")[0])
        response = response[:last_del]
        try:
            response_dict = json.loads(response, strict=False)
            return response
        except json.decoder.JSONDecodeError as a:
            e = str(a)


def split_response(response_dict):
    renaming_dict = {}
    response_string = ""
    improved_key = key_finder(["code", "Code", "improve"], response_dict)
    dict_key = key_finder(["dict", "Dict", "renaming", "operation"], response_dict)
    if improved_key is not None and dict_key is not None:
        improved_code = response_dict[improved_key]
        renaming_dict = response_dict[dict_key]

    elif len(response_dict) == 2:
        for key in response_dict:
            if "code" in key:
                improved_code = response_dict[key]
            else:
                if type(response_dict[key]) == dict:
                    for old, new in response_dict[key].items():
                        renaming_dict[old] = new
                elif type(response_dict[key]) == list:
                    for entry in response_dict[key]:
                        for old, new in entry.items():
                            renaming_dict[old] = new

    elif len(response_dict) == 3:
        for key in response_dict:
            if "code" in key or "Code" in key:
                improved_code = response_dict[key]
            elif "old" in key:
                old_key = key
            elif "new" in key:
                new_key = key
            else:
                raise InvalidResponseException("Invalid response format " + str(response_dict))
        if type(response_dict[old_key]) == list and type(response_dict[new_key]) == list:
            for old, new in zip(response_dict[old_key], response_dict[new_key]):
                renaming_dict[old] = new
        elif type(response_dict[old_key]) == dict and response_dict[new_key] == response_dict[old_key]:
            renaming_dict = response_dict[old_key]

    elif len(response_dict) == 1:
        print(response_dict)
        raise Exception("Only one Key in response dict")

    return improved_code, renaming_dict


def check_valid_code(code):
    if "{" not in code or "}" not in code or "(" not in code or ")" not in code:
        return False
    else:
        return True


def format_newlines_in_code(code):
    front = code.split('improved_code": "')[0]
    main = code.split('improved_code": "')[1].split('}",')[0]
    back = code.split('improved_code": "')[1].split('}",')[1]
    main = main.replace('\\', '\\\\')
    main = main.replace('\n', '\\n')
    main = main.replace('"', '\\"')
    main = main.replace('\'', '\\"')

    return front + 'improved_code": "' + main + '}\",' + back


def escape_failed_escapes(response_string):
    # original = response_string
    response_string = response_string.replace("\'\\x", "\'\\\\x")

    return response_string


def prompt_parallel(ai_module, result_queue, name, code, retries):
    try:
        # print(f"Starting {name}")
        if f"{name}\n" in code:
            for i in range(1, 20):
                code = code.replace(f"{name}\n{' ' * i}(", f"{name}(")
        result = ai_module.prompt_with_renaming(code, retries)
        result_queue.put((name, result))
    except KeyboardInterrupt:
        return

    except MaxTriesExceeded as e:
        print(f"Error in {name}")
        result_queue.put((name, "SKIP"))

    except OutOfTriesException as e:
        print(f"YOUR HARDLIMIT IS REACHED IN {name} , EXITING")
        result_queue.put((name, "EXIT"))

    except Exception as e:

        print(f"Error in {name}: {e} " + locator())
        print(f"Type: {type(e)}")

        result_queue.put((name, "SKIP"))


def fix_renaming_dict(renaming_dict, old_name):
    if renaming_dict is {}:
        raise Exception("Renaming dict is empty")


def locator(context=False):
    caller = getframeinfo(stack()[1][0])
    if context:
        return f"{caller.filename}:{caller.lineno} - {caller.code_context}"
    else:
        return f"{caller.filename}:{caller.lineno}"


def handle_spawn_worker(processes, prompting_args, started):
    if len(prompting_args) > 0:
        p = mp.Process(target=prompt_parallel, args=prompting_args.pop(0))
        p.start()
        processes.append(p)
        started += 1


def save_to_json(data, file):
    """
    if file is not a path to an existing file, it is assumed to be relative to PROJECTS_ROOT
    :param data:
    :param file:
    """
    if not os.path.exists(file):
        file = os.path.join(PROJECTS_ROOT, file)
    with open(file, "w") as f:
        json.dump(data, f, indent=4)


def save_to_csv(data, file):
    """
    if file is not a path to an existing file, it is assumed to be relative to PROJECTS_ROOT
    :param data:
    :param file:
    """
    if not os.path.exists(file):
        file = os.path.join(PROJECTS_ROOT, file)
    with open(file, "w") as f:
        writer = csv.writer(f)
        writer.writerows(data)


def filename(path):
    return os.path.basename(path).split(".")[0]


def to_snake_case(name):
    p1 = re.compile('(.)([A-Z][a-z]+)')
    p2 = re.compile('__([A-Z])')
    p3 = re.compile('([a-z0-9])([A-Z])')
    name = p1.sub(r'\1_\2', name)
    name = p2.sub(r'_\1', name)
    name = p3.sub(r'\1_\2', name)

    return name.lower()


def insert_missing_delimiter(response, exception):
    target = str(exception).split("delimiter:")[-1]
    char = int(target.split("char")[1].split(")")[0])
    line_wrap = ",\n" + (response[:char].split("\n")[-1])
    pre_wrap = response[:char].rstrip()
    fixed = pre_wrap + line_wrap + response[char:]
    return fixed


def insert_missing_double_quote(response, exception):
    # Expecting property name enclosed in double quotes: line 9 column 5 (char 252)
    target = str(exception).split("char ")[1].split(")")[0]
    char = int(target)
    pre = response[:char] + '"'
    if ":" in response[char:]:
        mid = response[char:].split(':')[0] + '":'
        post = response[char:].split(':',1)[1]
    else:
        print(response)
        print(exception)
        raise Exception("Could not find ':' in response")
    return pre + mid + post


def key_finder(key_parts, dictionary):
    """
    :param key_parts: list of key parts (strings) or single string
    :param dictionary: the dictionary to search in
    :return: search result
    """
    if type(key_parts) == str:
        key_parts = [key_parts]
    options = set()
    for key in dictionary.keys():
        for part in key_parts:
            if part in key:
                options.add(key)
    if len(options) == 1:
        return options.pop()
    elif len(options) > 1:
        print(dictionary)
        print(f"Multiple options found for {key_parts}: {options}")
        raise Exception(f"Multiple options found for {key_parts}: {options}")

    else:
        raise Exception(f"Could not find key {key_parts} in {dictionary}")


def clean_bad_renamings(renaming_dict, code, name):
    forbidden_strings = ["\\", "/", "*", "?", "\"", "<", ">", "|", " ", "PTR_", "DAT_", "FUNC_"]
    clean_dict = {}
    if name not in renaming_dict.keys():
        candidates = []
        for key in renaming_dict.keys():
            if name in key:
                candidates.append(key)
        if len(candidates) > 0:
            renaming_dict[name] = renaming_dict[candidates[0]]
            renaming_dict.pop(candidates[0])
        else:
            print(f"Could not find {name} in renaming dict{renaming_dict}")

    for old, new in renaming_dict.items():
        if old in code and (old != new):
            if new == "" or old == "":
                continue
            if any([forbidden in new or forbidden in old for forbidden in forbidden_strings]):
                continue
            if "FUN_" in old and name != old:
                continue
            try:
                val = hex(int(old, 16))
                continue
            except:
                pass
            try:
                val = hex(int(new, 16))
                continue
            except:
                pass
            if old in clean_dict.keys():
                raise Exception(f"Duplicate key {old} in renaming dict")
            clean_dict[old] = new

    return clean_dict


def do_renaming(renaming_dict, code, name):
    """
    Replaces all occurrences of keys in renaming_dict with their values in code.
    Cleans the renaming dict of bad entries and returns both the cleaned dict and the code with the names replaced.
    :param renaming_dict: dictionary of old names to new names
    :param code: the code to replace names in
    :param name: the name of the function
    :return: the code with the names replaced and the cleaned renaming dict
    """
    clean_dict = clean_bad_renamings(renaming_dict, code, name)
    temporary_remapping = {}
    clean_dict_sorted = dict(sorted(clean_dict.items(), key=lambda item: (-len(item[0]), item[0])))

    for old, new in clean_dict_sorted.items():
        rand_str = get_random_string(10)
        temporary_remapping[rand_str] = new
        code = code.replace(old, rand_str)
    for tag, new in temporary_remapping.items():
        code = code.replace(tag, new)
    return code, clean_dict
