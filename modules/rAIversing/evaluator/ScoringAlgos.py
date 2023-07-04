import difflib, re
import json
import os

from rAIversing.evaluator.utils import tokenize_name_v1
from rAIversing.utils import to_snake_case
from rAIversing.pathing import EXPANDERS_ROOT
from xfl.xfl.src.symbolnlp import SymbolNLP


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

for file in os.listdir(EXPANDERS_ROOT):
    with open(os.path.join(EXPANDERS_ROOT, file)) as f:
        replacement_dict_part = json.load(f)
        replacement_dict.update(replacement_dict_part)

nlp = SymbolNLP()




def calc_score(original, predicted, entrypoint):

    if "FUNC" in predicted:
        return 0.0
    #return calc_score_v3(original, predicted, entrypoint)
    #return calc_score_punstrip(original, predicted, entrypoint)
    return calc_score_dev_hybrid(original, predicted, entrypoint)

def calc_score_v1(original, predicted, entrypoint):
    #original = original.lower().replace(f"_{entrypoint.replace('0x', '')}", "")
    original = to_snake_case(original).replace(f"_{entrypoint.replace('0x', '')}", "")
    #predicted = predicted.lower().replace(f"_{entrypoint.replace('0x', '')}", "")
    predicted = to_snake_case(predicted).replace(f"_{entrypoint.replace('0x', '')}", "")


    score = 0.0
    #print(to_snake_case(original), to_snake_case(predicted))


    # remove duplicates from similarity_indicators
    similarity_indicators_local = list(set(similarity_indicators))

    if original in predicted or predicted in original:
        return 1.0

    for indicator in similarity_indicators:
        if indicator in original and indicator in predicted:
            score = 1.0
            break
        elif "nothing" in predicted:
            score = 0.042
            break
    if score == 0.0:
        score = calc_group_similarity(original, predicted)

    for old, new in replacement_dict.items():
        if new not in original and old == original:
            original = original.replace(old, new)
            break
    if score == 0.0:
        for indicator in similarity_indicators:
            if indicator in original and indicator in predicted:
                score = 1.0
                break
            elif "nothing" in predicted:
                score = 0.042
                break

    if score == 0.0:
        score = calc_group_similarity(original, predicted)

    if score == 0.0:
        score = difflib.SequenceMatcher(None, original, predicted).ratio()
    return score


def calc_score_v2(original, predicted, entrypoint):
    original = original.lower().replace(f"_{entrypoint.replace('0x', '')}", "")
    predicted = predicted.lower().replace(f"_{entrypoint.replace('0x', '')}", "")

    original_tokens = set(tokenize_name_v1(original))
    predicted_tokens = set(tokenize_name_v1(predicted))

    if len(original_tokens.intersection(predicted_tokens)) > 0:
        return 1.0
    else:
        #return 0.0
        return calc_score_v1(original, predicted, entrypoint)

def calc_score_v3(original, predicted, entrypoint):

    for old, new in replacement_dict.items():
        if new not in original and old == original:
            original = original.replace(old, new)
            break

    original = to_snake_case(original).replace(f"_{entrypoint.replace('0x', '')}", "")
    predicted = to_snake_case(predicted).replace(f"_{entrypoint.replace('0x', '')}", "")

    if "do_nothing" in predicted:
        return 0.0

    if "reverse" in predicted and "engineer" in predicted:
        return 0.0

    if "improve" in predicted and "function" in predicted:
        return 0.0




    original_tokens = set(tokenize_name_v1(original))
    predicted_tokens = set(tokenize_name_v1(predicted))

    if len(original_tokens.intersection(predicted_tokens)) > 0:
        return 1.0

    if original in predicted or predicted in original:
        return 1.0

    score = calc_group_similarity(original, predicted)


    if score == 0.0:
        score = difflib.SequenceMatcher(None, original, predicted).ratio()
    return score



def calc_score_punstrip(original, predicted, entrypoint):

    for old, new in replacement_dict.items():
        if new not in original and old == original:
            original = original.replace(old, new)
            break

    original = to_snake_case(original).replace(f"_{entrypoint.replace('0x', '')}", "")
    predicted = to_snake_case(predicted).replace(f"_{entrypoint.replace('0x', '')}", "")

    if "do_nothing" in predicted:
        return 0.0

    if "reverse" in predicted and "engineer" in predicted:
        return 0.0

    if "improve" in predicted and "function" in predicted:
        return 0.0


    #lhs = nlp.canonical_set(original)
    #rhs = nlp.canonical_set(predicted)

    score = nlp.wordnet_similarity(original, predicted)
    assert 0.0 <= score <= 1.0
    # eq = nlp.check_word_similarity(old, new)
    # sm = SmithWaterman()
    # smd = sm.distance(nlp.canonical_name(old), nlp.canonical_name(new))
    # print(old, new, eq, score, smd)
    return score


def calc_score_dev_hybrid(original, predicted, entrypoint):
    original = original.lower().replace(f"_{entrypoint.replace('0x', '')}", "")
    predicted = predicted.lower().replace(f"_{entrypoint.replace('0x', '')}", "")

    original_string = original
    predicted_string = predicted

    for old, new in replacement_dict.items():
        if new not in original and old == original:
            original = original.replace(old, new)
            break

    original = to_snake_case(original)
    predicted = to_snake_case(predicted)

    if "do_nothing" in predicted:
        return 0.0

    if "reverse" in predicted and "engineer" in predicted:
        return 0.0

    if "improve" in predicted and "function" in predicted:
        return 0.0

    original_tokens = set(tokenize_name_v1(original))
    predicted_tokens = set(tokenize_name_v1(predicted))

    if len(original_tokens.intersection(predicted_tokens)) > 0:
        return 1.0
    score = calc_group_similarity(original, predicted)
    if score != 0.0:
        return score

    score = nlp.wordnet_similarity(original, predicted)
    assert 0.0 <= score <= 1.0

    return score




def calc_group_similarity(original_function_name, reversed_function_name):
    for group in similarity_indicator_groups:
        if re.match(group[0], original_function_name) and re.match(group[1], reversed_function_name):
            return 1.0
    return 0.0
