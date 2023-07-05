import json
import logging
import time

import requests
import revChatGPT.V3
import tiktoken
from revChatGPT.typings import *
from rich.console import Console

from rAIversing.AI_modules import AiModuleInterface
from rAIversing.AI_modules.openAI_core.PromptEngine import PromptEngine
from rAIversing.pathing import *
from rAIversing.utils import extract_function_name, NoResponseException, clear_extra_data, check_valid_code, \
    MaxTriesExceeded, InvalidResponseException, format_newlines_in_code, escape_failed_escapes, \
    check_reverse_engineer_fail_happend, locator, insert_missing_delimiter, do_renaming, \
    IncompleteResponseException, insert_missing_double_quote, HardLimitReached


def assemble_prompt_v1(code):
    pre = """
You have been given the decompiled code of a function that has been extracted from a binary that needs to be reverse engineered and improved.
The original code is as follows:

"""
    post = """
    
    Your task is to create an improved and more readable version of the code without changing variables starting with "PTR_" or "DAT_".
    Give the function a more descriptive name that closely describes what it does.  
        
    Your response should include the following:
        A dictionary that maps the original names of the function, parameters and variables to their new names in the improved code.
        
    DO ONLY respond in the following format:
        
        {
        "<original_function_name>": "<new_function_name>",
        "<original_parameter_name_1>": "<new_parameter_name_1>",
        "<original_parameter_name_2>": "<new_parameter_name_2>",
        ...
        "<original_variable_name_1>": "<new_variable_name_1>",
        "<original_variable_name_2>": "<new_variable_name_2>",
        ...
        }
        
    Do not use single quotes. No Explanation is needed.
    Do NOT rename the function to "reverse_engineered", "improved_function" or similar.
"""

    return pre + code + post


def assemble_prompt_v2(code):
    pre = """
    You are provided with a piece of code that appears to be decompiled from a binary, possibly including common libraries.
    Your task is to create a more readable version of the code that closely resembles the original code.

    Code:
    """

    post = """
    [Prompt]:

    You have been provided with a decompiled function from a binary, which may include common libraries.
    Your task is to make the code more readable while preserving the original structure and logic.
    Please ensure that the resulting code resembles the original as closely as possible.
    Keep in mind that the original function likely has a similar functionality to a library function.
    Your task is to identify and provide the name of the library function that best matches the functionality of the given code as restored_function_name.

    Please provide the name of the library function that closely resembles the functionality of the provided code.

    DO ONLY respond in the following format:
        
        {
        "<original_function_name>": "<restored_function_name>",
        "<original_parameter_name_1>": "<new_parameter_name_1>",
        "<original_parameter_name_2>": "<new_parameter_name_2>",
        ...
        "<original_variable_name_1>": "<new_variable_name_1>",
        "<original_variable_name_2>": "<new_variable_name_2>",
        ...
        }
    
    Do not use single quotes. No Explanation is needed.
    Do NOT rename the function to "reverse_engineered", "improved_function" or similar.
    """

    return pre + code + post




def api_key(path_to_api_key=DEFAULT_API_KEY_PATH, engine=PromptEngine.DEFAULT):
    chat = ChatGPTModule()
    chat.init_api(path_to_api_key, engine=engine)
    return chat


class ChatGPTModule(AiModuleInterface):
    def __init__(self):
        self.chat_small = None  # type: revChatGPT.V3.Chatbot
        self.chat_medium = None  # type: revChatGPT.V3.Chatbot
        self.chat_large = None  # type: revChatGPT.V3.Chatbot
        self.api_key = None
        self.api_key_path = None
        self.logger = logging.getLogger("ChatGPTModule")
        self.console = Console()
        self.engine = PromptEngine.DEFAULT

    def get_model_name(self):
        return self.engine.value

    def init_api(self, path_to_api_key=DEFAULT_API_KEY_PATH, engine=PromptEngine.DEFAULT):
        self.engine = engine
        self.api_key_path = path_to_api_key
        with open(self.api_key_path) as f:
            self.api_key = f.read().strip()
            if self.api_key == "":
                raise Exception("API Key is empty")

        # self.chat_small = revChatGPT.V3.Chatbot(api_key=self.api_key,engine=self.engine.small())
        # self.chat_medium = revChatGPT.V3.Chatbot(api_key=self.api_key, engine=self.engine.medium())
        # self.chat_large = revChatGPT.V3.Chatbot(api_key=self.api_key, engine=self.engine.large())
        trunc_offset = 100

        self.chat_small = revChatGPT.V3.Chatbot(api_key=self.api_key, engine=self.engine.small(),
                                                max_tokens=max(self.engine.small_range())+trunc_offset,
                                                truncate_limit=max(self.engine.small_range()))
        self.chat_medium = revChatGPT.V3.Chatbot(api_key=self.api_key, engine=self.engine.medium(),
                                                 max_tokens=max(self.engine.medium_range()) + trunc_offset,
                                                 truncate_limit=max(self.engine.medium_range()))
        self.chat_large = revChatGPT.V3.Chatbot(api_key=self.api_key, engine=self.engine.large(),
                                                max_tokens=max(self.engine.large_range()) + trunc_offset,
                                                truncate_limit=max(self.engine.large_range()))

    def get_max_tokens(self):
        return max(self.engine.large_range())

    def assemble_prompt(self, input_code):
        return assemble_prompt_v1(input_code)

    def prompt(self, prompt,try_larger=False):  # type: (str,int) -> (str,int)
        """Prompts the model and returns the result and the number of used tokens"""
        # self.console.print("Prompting ChatGPT with: " + str(self.calc_used_tokens(prompt)) + " tokens")
        needed_tokens = self.calc_used_tokens(prompt)
        used_tokens = 0
        answer = ""

        if needed_tokens > self.get_max_tokens():
            raise Exception("Used more tokens than allowed: " + str(needed_tokens) + " > " + str(self.get_max_tokens()))
        elif needed_tokens in self.engine.large_range() or try_larger:
            answer = self.chat_large.ask(prompt)
            if "{" not in answer:
                print(f"messages: {self.chat_large.conversation['default']}")
                print(f"Answer: {answer}" + locator())
                print(f"length of messages: {len(self.chat_large.conversation['default'])}")
            self.chat_large.conversation["default"].pop()
            used_tokens = self.chat_large.get_token_count()
            self.chat_large.reset()
            time.sleep(30)
        elif needed_tokens in self.engine.medium_range():
            answer = self.chat_medium.ask(prompt)
            if "{" not in answer:
                print(f"messages: {self.chat_medium.conversation['default']}")
                print(f"Answer: {answer}" + locator())
            self.chat_medium.conversation["default"].pop()
            used_tokens = self.chat_medium.get_token_count()
            self.chat_medium.reset()
            time.sleep(30)
        elif needed_tokens in self.engine.small_range():
            answer = self.chat_small.ask(prompt)
            if "{" not in answer:
                print(f"Answer: {answer}" + locator())
                print(f"tokens: {self.chat_small.get_token_count()}")
                print(f"needed tokens: {needed_tokens}")
            self.chat_small.conversation["default"].pop()
            used_tokens = self.chat_small.get_token_count()
            self.chat_small.reset()
        else:
            raise Exception("Used more tokens than allowed: " + str(needed_tokens) + " > " + str(self.get_max_tokens()))
        if answer is None or answer == "":
            raise NoResponseException("No Answer from Chat (empty string)")

        return answer.replace("<|im_sep|>", ""), used_tokens

    def remove_plaintext_from_response(self, response):  # type: (str) -> str
        """Removes everything from the response before the first { and after the last }"""
        return response[response.find("{"):response.rfind("}") + 1]

    def format_string_correctly(self, string):
        string = string.replace('\\', '\\\\')
        return string

    def remove_trailing_commas(self, string):
        string = string.replace(',\n}', '\n}')
        string = string.replace(',\n }', '\n }')
        string = string.replace(',\n  }', '\n  }')
        string = string.replace(',\n   }', '\n   }')
        return string

    def any_dict_to_renaming_dict(self, any_dict):
        pass

    def postprocess_code(self, code):
        out = code.replace("\n\\n", "\n")
        return out.replace('\\\\', '\\')

    def process_response(self, response_string_orig):
        try:
            response_dict = json.loads(response_string_orig, strict=False)
            return response_dict
        except:
            pass

        response_string = self.remove_plaintext_from_response(response_string_orig)
        if response_string == "":
            raise IncompleteResponseException("Respond Incomplete, closing bracket missing")

        try:
            response_dict = json.loads(response_string, strict=False)
            return response_dict
        except:
            pass

        response_string = self.remove_trailing_commas(response_string)
        try:
            response_dict = json.loads(response_string, strict=False)
            return response_dict
        except:
            pass

        response_string = self.add_missing_commas(response_string)
        try:
            response_dict = json.loads(response_string, strict=False)
            return response_dict
        except:
            pass

        response_string = escape_failed_escapes(response_string)
        try:
            response_dict = json.loads(response_string, strict=False)
            return response_dict
        except:
            pass

        try:
            response_string = format_newlines_in_code(response_string)
            # For cases where the code is not escaped and contains double quotes

            response_dict = json.loads(response_string, strict=False)
            return response_dict
        except:
            pass

        if '```\n\n```' in response_string:
            response_string = response_string.replace('```\n\n```', '\n####\n')
            splits = response_string.split('####')
            temp_dict = {}
            try:
                rename_dict = json.loads(splits[0], strict=False)
                temp_dict["code"] = splits[1]
            except Exception as e:
                self.logger.error("Ended Up here AAA")
                pass
            try:
                rename_dict = json.loads(splits[1], strict=False)
                temp_dict["code"] = splits[0]
            except Exception as e:
                self.logger.error("Ended Up here BBB")
                pass

            # TODO: check if temp_dict is empty
        if '```' in response_string:
            response_string = response_string.replace('```', '')
        if '`' in response_string:
            response_string = response_string.replace('`', '"')
        if """'""" in response_string:
            response_string = response_string.replace("""'""", '"')
        ideas_left = True
        max_delimiter_insertions = 5
        max_double_quote_insertions = 20

        while ideas_left:
            try:
                response_dict = json.loads(response_string, strict=False)
                break


            except Exception as e:
                if """Expecting ',' delimiter:""" in str(e):
                    if max_delimiter_insertions != 0:
                        response_string = insert_missing_delimiter(response_string, e)
                        max_delimiter_insertions -= 1
                        continue

                    self.logger.exception(e)
                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(response_string_orig)
                    print(f"###### RESPONSE START @ {locator()}######")

                    print(response_string_orig)
                    print(f"###### RESPONSE END @ {locator()}######")
                    print(f"###### CURRENT STATE @ {locator()}######")
                    print(response_string)
                    print(f"###### CURRENT STATE END @ {locator()}######")
                elif "Extra data" in str(e):
                    try:
                        response_string = clear_extra_data(response_string, e)
                        continue
                    except Exception as e2:
                        with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                            f.write(response_string_orig)
                        print(e2)
                        print(f"###### RESPONSE START @ {locator()}######")

                        print(response_string_orig)
                        print(f"###### RESPONSE END @ {locator()}######")
                        print(f"###### CURRENT STATE @ {locator()}######")
                        print(response_string)
                        print(f"###### CURRENT STATE END @ {locator()}######")
                        pass
                elif "Expecting property name enclosed in double quotes" in str(e):
                    if max_double_quote_insertions != 0:
                        response_string = insert_missing_double_quote(response_string, e)
                        max_double_quote_insertions -= 1
                        continue



                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(response_string_orig)
                    print(e)
                    print(f"###### RESPONSE START @ {locator()}######")
                    print(response_string_orig)
                    print(f"###### RESPONSE END @ {locator()}######")
                    print(f"###### CURRENT STATE @ {locator()}######")
                    print(response_string)
                    print(f"###### CURRENT STATE END @ {locator()}######")
                    ideas_left = False
                    pass
                else:
                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(response_string_orig)
                    print(e)
                    print(f"###### RESPONSE START @ {locator()}######")
                    print(response_string_orig)
                    print(f"###### RESPONSE END @ {locator()}######")
                    print(f"###### CURRENT STATE @ {locator()}######")
                    print(response_string)
                    print(f"###### CURRENT STATE END @ {locator()}######")
                    raise e

        return response_dict

    def prompt_with_renaming(self, input_code, retries=5):  # type: (str,int) -> (str, dict)
        """Prompts the model and returns the resulting code and a dict of renamed Names
            This version uses the new prompt format and is more efficient than the old one
            It only asks the model for the renaming dict and then applies it to the code
        """
        full_prompt = self.assemble_prompt(input_code)
        renaming_dict = {}
        response_string = ""
        response_string_orig = ""
        # print(full_prompt)
        old_func_name = extract_function_name(input_code)
        if old_func_name is None or old_func_name == "":
            raise Exception(f"No function name found in input code {input_code}")
        try_larger=False
        total_tokens_used = 0
        for i in range(0, retries):
            e = " " or str(e)
            try:
                response_string_orig, used_tokens = self.prompt(full_prompt,try_larger)
                total_tokens_used += used_tokens
                response_dict = self.process_response(response_string_orig)
                improved_code, renaming_dict = do_renaming(response_dict, input_code, old_func_name)
                # with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                #   f.write(response_string_orig)

                try:
                    new_func_name = renaming_dict[old_func_name]
                except:
                    self.console.log(
                        f"[blue]{old_func_name}[/blue]: [orange3]not in Response, Retry  {i + 1}/{retries}[/orange3]")
                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(response_string_orig)
                    continue

                if new_func_name is None or new_func_name == "":
                    self.console.log(
                        f"[blue]{old_func_name}[/blue]:[orange3]Got invalid code from model, Retry  {i + 1}/{retries}[/orange3]")
                    continue

                if check_reverse_engineer_fail_happend(improved_code):
                    self.console.log(
                        f"[blue]{old_func_name}[/blue]:[orange3]Got reverse engineer fail from model, Retry  {i + 1}/{retries}[/orange3]")
                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(response_string_orig)
                    continue

                if check_valid_code(improved_code):
                    improved_code = self.postprocess_code(improved_code)
                    if improved_code == input_code:
                        raise Exception("No change")
                    return improved_code, renaming_dict, total_tokens_used,i
                else:
                    self.console.log(
                        f"[blue]{old_func_name}[/blue]:[orange3]Got invalid code from model, Retry  {i + 1}/{retries}[/orange3]")
                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(response_string_orig)
                        f.write("\n\n")
                        f.write(improved_code)
                    continue

            except NoResponseException as e:
                raise e

            except IncompleteResponseException as e:
                if i >= retries - 1:
                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(response_string_orig)
                    self.console.log(response_string_orig)
                    raise MaxTriesExceeded("Max tries exceeded " + str(e) + locator())
                if i >= (retries - 1) / 2:
                    try_larger = True
                self.console.log(
                    f"[blue]{old_func_name}[/blue]:[orange3]Got incomplete response from model, Retry  {i + 1}/{retries}! Is it maybe too long: {self.calc_used_tokens(full_prompt)}[/orange3]")
                with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                    f.write(response_string_orig)
                continue

            except json.JSONDecodeError as e:
                if i >= retries - 1:
                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(response_string_orig)
                    self.console.log(response_string_orig)
                    raise MaxTriesExceeded("Max tries exceeded " + str(e) + locator())
                if "Expecting value: line 1 column 1 (char 0)" in str(e) or "Unterminated string starting at:" in str(
                        e):
                    self.console.log(
                        f"[blue]{old_func_name}[/blue]:[orange3]Got incomplete response from model, Retry  {i + 1}/{retries}! Is it maybe too long: {self.calc_used_tokens(full_prompt)}[/orange3]")
                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(response_string_orig)
                    if i > 1:
                        continue

                    if len(full_prompt) // 2 > len(response_string_orig) > len(full_prompt) // 4:
                        self.logger.warning(f"Response was: {response_string_orig}")
                        self.logger.warning(f"Prompt was: {full_prompt}")
                    continue
                else:
                    self.logger.warning(f"Response was: {response_string_orig}")
                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(response_string_orig)
                    self.logger.exception(e)
                    raise e
            except APIConnectionError as e:

                if i >= retries - 1:
                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(e)
                    raise MaxTriesExceeded("Max tries exceeded " + locator())

                if "Too Many Requests" in str(e):

                    if "You exceeded your current quota, please check your plan and billing details." in str(e):
                        raise HardLimitReached(f"Your HardLimit is reached!!!!")
                    if "That model is currently overloaded with other requests" in str(e):
                        self.console.log(
                            f"[blue]{old_func_name}[/blue]:[orange3] [red]Model Overloaded!![/red], will sleep now! Retry {i + 1}/{retries}[/orange3]")
                    else:
                        self.console.log(
                            f"[blue]{old_func_name}[/blue]:[orange3]Got [red]Too many requests[/red] from model, will sleep now! Retry {i + 1}/{retries}[/orange3]")
                    time.sleep(120)
                    continue
                else:
                    self.logger.exception(e)
                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(e)
                    raise e

            except InvalidResponseException as e:
                with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                    f.write(response_string_orig)
                self.console.log(
                    f"[blue]{old_func_name}[/blue]:[orange3]Got InvalidResponseException {str(e)}, Retry  {i + 1}/{retries}[/orange3]")
                if i >= retries - 1:
                    raise MaxTriesExceeded("Max tries exceeded " + locator())
                continue
            except requests.exceptions.ChunkedEncodingError as e:
                if i >= retries - 1:
                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(response_string_orig)
                    raise MaxTriesExceeded("Max tries exceeded " + locator())
                self.console.log(
                    f"[blue]{old_func_name}[/blue]:[orange3]Got ChunkedEncodingError, Retry  {i + 1}/{retries}!")
                continue

            except TypeError as e:
                print(f"###### RESPONSE START @ {locator()} ######")
                print(response_string_orig)
                print(f"###### RESPONSE END @ {locator()} ######")
                self.logger.exception(e)
                self.logger.error(locator())
                self.logger.error(f"Critical error, aborting")
                exit(-1)

            except Exception as e:
                self.logger.warning(f"Type of error: {type(e)}")
                if "The server is overloaded or not ready yet." in str(e):
                    self.logger.warning(f"Got server overload from model, aborting")
                    exit(-1)

                if "max_tokens" in str(e):
                    raise Exception("Function too long, skipping!")
                else:
                    self.logger.exception(e)
                    print("###### RESPONSE START ######")
                    print(response_string_orig)
                    print("###### RESPONSE END ######")
                    raise Exception(e)
        with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
            f.write(response_string_orig)

        self.console.log(f"[blue]{old_func_name}[/blue]:[orange3] Max Tries Exceeded[/orange3]")
        raise MaxTriesExceeded("Max tries exceeded " + locator())

    def calc_used_tokens(self, function):
        """Calculates the used tokens for a given function, based on the engine
        and a multiplier of 1.015 to account for the lenght of the response.
        It is an approximation, that is designed to be more accurate for bigger functions,
        in order to get as close to the limit as possible, without exceeding it.
        """

        if self.engine == PromptEngine.HYBRID:
            enc = tiktoken.encoding_for_model("gpt-4")
        elif "gpt-4" in self.engine.value or "gpt-3.5" in self.engine.value:
            enc = tiktoken.encoding_for_model("gpt-4")
        else:
            raise NotImplementedError(f"Engine {self.engine} not supported yet!" + locator())
        return int(1.015 * len(enc.encode(function)))

    def add_missing_commas(self, response_string):
        """Adds missing commas to the response string"""
        response_string = response_string.replace('\"\n\"', '\",\n\"')
        response_string = response_string.replace('\"\n \"', '\",\n \"')
        response_string = response_string.replace('\"\n  \"', '\",\n  \"')
        response_string = response_string.replace('\"\n   \"', '\",\n   \"')
        response_string = response_string.replace('\"\n    \"', '\",\n    \"')

        return response_string
