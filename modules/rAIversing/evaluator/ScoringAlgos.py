import json, difflib, re, shutil

from rich.console import Console, CONSOLE_SVG_FORMAT
from rich.table import Table, Column

from rAIversing.Engine import rAIverseEngine
from rAIversing.Ghidra_Custom_API import binary_to_c_code, import_changes_to_ghidra_project, \
    import_changes_to_existing_project, existing_project_to_c_code

from rAIversing.pathing import *


# This is a list of mostly verbs that, if present, describe the intended functionality of a function.
# If two functions share the same verb, they are highly likely to be similar.
# For example, if two functions have "send" in their name, they are likely to both send data.
# Or if two functions have "encrypt" in their name, they are likely to both encrypt data.
similarity_indicators = ["send", "get", "encode", "decode", "set", "init", "process", "time", "device", "memory",
                         "hash", "checksum", "check", "verify", "update", "convert", "combine"
                                                                                     "execute", "calculate", "calc", "encrypt", "decrypt",
                         "parse", "print", "setup", "alarm", "alloc", "error", "write", "read", "find", "string", "free", "flag", "message",
                         "call", "seek", "loop", "execute", "run", "main", "start", "stop", "exit", "return", "check", "verify", "update",
                         "convert", "combine", "clear", "list", "char"]

# The following are groups of similarity indicators that are likely to be used together,
# and regarding that the modell (chatGPT) currently produces rather natural language as function names,
# whereas the debug symbols are rather short and often not very descriptive,
# or just more abstract and not on the machine level,
# we can map a one or more "words" or "sentences" to one or more natural language styled "words" or "sentences".
# For example, if the debug symbol contains "activate" or "start", we can map it to "set...bit" or "set...flag",
# which are more likely to be used in the natural language styled function names.
# Another example would be "deactivate" or "stop", which we can map to "clear...bit" or "clear...flag".
# This is a list of lists, where each list contains a list of regexes that are likely to be used together.
# TODO sendData -> write..Memory/...
# TODO receiveData -> read..Memory/... ???
# TODO DeInit -> free???/deactivate...Memory/... ???
# TODO memcpy -> copy...Memory/... ???
# main -> run ... ???
# validate -> check... ???
similarity_indicator_groups = [[r"^(.*(stop|disable|end).*)+$", r"^(.*(clear){1}.*(bit|flag|memory).*)+$"],
                               [r'^(?!.*deactivate).*(?:activate|enable|start).*$',
                                r"^(?!.*deactivate).*((set){1}.*?(bit|flag|memory)|(?:activate|enable|start)).*$"]]

# As library functions usually use shorted names (strchr,strrchr), we need to map the common ones
# to their full / natural language styled names (find_character_in_string, find_last_character_in_string).
replacement_dict = {"strchr": "find_character_in_string", "strrchr": "find_last_character_in_string",
                    "memcpy": "copy_memory", "memset": "set_memory", "malloc": "allocate_memory", "strcpy": "copy_string",
                    "strlen": "string_length", "strcat": "concatenate_strings", "strncat": "concatenate_strings",
                    "strcmp": "compare_strings", "strncmp": "compare_strings", "memchr": "find_character_in_memory",
                    "memset": "set_memory", "memmove": "move_memory", "div": "divide", "toInt": "convert_to_integer"

                    }


def calc_score_v1(original_function_name, reversed_function_name, entrypoint):
    original_function_name = original_function_name.lower().replace(f"_{entrypoint.replace('0x', '')}", "")
    reversed_function_name = reversed_function_name.lower().replace(f"_{entrypoint.replace('0x', '')}", "")
    score = 0.0
    # remove duplicates from similarity_indicators
    similarity_indicators_local = list(set(similarity_indicators))

    for indicator in similarity_indicators:
        if indicator in original_function_name and indicator in reversed_function_name:
            score = 1.0
            break
        elif "nothing" in reversed_function_name:
            score = 1.0
            break
    if score == 0.0:
        score = calc_group_similarity(original_function_name, reversed_function_name)

    for old, new in replacement_dict.items():
        if new not in original_function_name and old == original_function_name:
            original_function_name = original_function_name.replace(old, new)
            break
    if score == 0.0:
        for indicator in similarity_indicators:
            if indicator in original_function_name and indicator in reversed_function_name:
                score = 1.0
                break
            elif "nothing" in reversed_function_name:
                score = 1.0
                break

    if score == 0.0:
        score = calc_group_similarity(original_function_name, reversed_function_name)

    if score == 0.0:
        score = difflib.SequenceMatcher(None, original_function_name, reversed_function_name).ratio()
    return score


def calc_group_similarity(original_function_name, reversed_function_name):
    for group in similarity_indicator_groups:
        if re.match(group[0], original_function_name) and re.match(group[1], reversed_function_name):
            return 1.0
    return 0.0
