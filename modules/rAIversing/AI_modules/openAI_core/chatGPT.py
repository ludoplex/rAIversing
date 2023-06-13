import json
import logging
import time
import requests

import revChatGPT.V1
import revChatGPT.V3
import tiktoken
from revChatGPT.typings import *
from rich.console import Console

from rAIversing.AI_modules import AiModuleInterface
from rAIversing.pathing import *
from rAIversing.utils import extract_function_name, NoResponseException, clear_extra_data, split_response, \
    check_valid_code, MaxTriesExceeded, InvalidResponseException, format_newlines_in_code, escape_failed_escapes, \
    check_reverse_engineer_fail_happend, locator, OutOfTriesException, insert_missing_delimiter
from rAIversing.AI_modules.openAI_core.PromptEngine import PromptEngine

PROMPT_TEXT = """
    
    Respond with a single JSON object containing the following keys and values:
    improved_code : make the following code more readable without changing variables starting with PTR_ , DAT_ or FUN_
    renaming_operations : list all changes in json format with keys being the old names and the values the corresponding new names.
    Do not use single quotes
    
    Original code:
    """


def assemble_prompt_v1(code):
    return PROMPT_TEXT + code


def assemble_prompt_v2(code):
    pre = """
You have been given a piece of C code which needs to be reverse engineered and improved. The original code is as follows:
        
"""
    post = """
        
        Your task is to create an improved and more readable version of the code without changing variables starting with "PTR_" or "DAT_".
        If possible give the function a more descriptive name, otherwise leave it as it is. (Functions start with "FUN_") 
        
        Your response should include the following:
                        
        1. The improved code, which should be more readable and easier to understand. Do not use single characters for variable names.
        2. A dictionary that maps the original names of the function, parameters and variables to their new names in the improved code.
        
        Respond in the following format:
        
        {
        "improved_code": "<your escaped and improved code here>",
        "renaming_operations": {
        "<original_function_name>": "<new_function_name>",
        "<original_parameter_name_1>": "<new_parameter_name_1>",
        "<original_parameter_name_2>": "<new_parameter_name_2>",
        ...
        "<original_variable_name_1>": "<new_variable_name_1>",
        "<original_variable_name_2>": "<new_variable_name_2>",
        ...
        }
        }
        Do not use single quotes. No Explanation is needed.
        """

    return pre + code + post


def api_key(path_to_api_key=DEFAULT_API_KEY_PATH, engine=PromptEngine.DEFAULT):
    chat = ChatGPTModule()
    chat.init_api(path_to_api_key, engine=engine)
    return chat



class ChatGPTModule(AiModuleInterface):
    def __init__(self):
        self.chat_small = None # type: revChatGPT.V3.Chatbot
        self.chat_medium = None # type: revChatGPT.V3.Chatbot
        self.chat_large = None # type: revChatGPT.V3.Chatbot
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
            self.api_key = f.read()
            if self.api_key == "":
                raise Exception("API Key is empty")
        self.chat_small = revChatGPT.V3.Chatbot(api_key=self.api_key)
        self.chat_medium = revChatGPT.V3.Chatbot(api_key=self.api_key, engine="gpt-4")
        #self.chat_large = revChatGPT.V3.Chatbot(api_key=self.api_key, engine="gpt-4-32k-0314")
        self.chat_large = revChatGPT.V3.Chatbot(api_key=self.api_key, engine="gpt-4") #TODO change back once gpt-4-32k is available

    def get_max_tokens(self):
        if self.engine == PromptEngine.GPT_3_5_TURBO:
            return 3500
        elif self.engine == PromptEngine.GPT_4:
            #return 30500 #TODO change back to 30500 once gpt-4-32k is available
            return 7000
        elif self.engine == PromptEngine.HYBRID:
            #return 30500 #TODO change back to 30500 once gpt-4-32k is available
            return 7000

    def assemble_prompt(self, input_code):
        return assemble_prompt_v2(input_code)

    def prompt(self, prompt):  # type: (str) -> (str,int)
        """Prompts the model and returns the result and the number of used tokens"""
        #self.console.print("Prompting ChatGPT with: " + str(self.calc_used_tokens(prompt)) + " tokens")
        needed_tokens = self.calc_used_tokens(prompt)
        used_tokens = 0
        answer = ""
        if needed_tokens > self.get_max_tokens():
            raise Exception("Used more tokens than allowed: " + str(needed_tokens) + " > " + str(self.get_max_tokens()))
        elif needed_tokens > 7000 and (self.engine == PromptEngine.GPT_4 or self.engine == PromptEngine.HYBRID):

            answer = self.chat_large.ask(prompt)
            self.chat_large.conversation["default"].pop()
            used_tokens = self.chat_large.get_token_count()
            self.chat_large.reset()
            time.sleep(30)
        elif needed_tokens > 3500 and (self.engine == PromptEngine.GPT_4 or self.engine == PromptEngine.HYBRID):
            answer = self.chat_medium.ask(prompt)
            self.chat_medium.conversation["default"].pop()
            used_tokens = self.chat_medium.get_token_count()
            self.chat_medium.reset()
            time.sleep(30)
        else:
            answer = self.chat_small.ask(prompt)
            self.chat_small.conversation["default"].pop()
            used_tokens = self.chat_small.get_token_count()
            self.chat_small.reset()
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
            return response_dict, response_string_orig
        except:
            pass

        response_string = self.remove_plaintext_from_response(response_string_orig)
        try:
            response_dict = json.loads(response_string, strict=False)
            return response_dict, response_string_orig
        except:
            pass

        # response_string = self.format_string_correctly(response_string)
        # try:
        #    response_dict = json.loads(response_string, strict=False)
        #    return response_dict, response_string_orig
        # except:
        #    pass

        response_string = self.remove_trailing_commas(response_string)
        try:
            response_dict = json.loads(response_string, strict=False)
            return response_dict, response_string_orig
        except:
            pass

        response_string = self.add_missing_commas(response_string)
        try:
            response_dict = json.loads(response_string, strict=False)
            return response_dict, response_string_orig
        except:
            pass

        response_string = escape_failed_escapes(response_string)
        try:
            response_dict = json.loads(response_string, strict=False)
            return response_dict, response_string_orig
        except:
            pass

        try:
            response_string = format_newlines_in_code(response_string)
            # For cases where the code is not escaped and contains double quotes

            response_dict = json.loads(response_string, strict=False)
            return response_dict, response_string_orig
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
        ideas_left = True
        max_delimiter_insertions = 1
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
                    print(f"###### RESPONSE START @ {locator()}######")
                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(response_string_orig)

                    print(response_string_orig)
                    print(f"###### RESPONSE END @ {locator()}######")
                    print(f"###### CURRENT STATE @ {locator()}######")
                    print(response_string)
                    print(f"###### CURRENT STATE END @ {locator()}######")
                elif "Extra data" in str(e):
                    try:
                        response_dict = clear_extra_data(response_string, e)
                        break
                    except Exception as e2:
                        pass

                raise e

        return response_dict, response_string_orig

    def prompt_with_renaming(self, input_code, retries=5):  # type: (str,int) -> (str, dict)
        """Prompts the model and returns the resulting code and a dict of renamed Names"""
        full_prompt = assemble_prompt_v2(input_code)
        renaming_dict = {}
        response_string = ""
        response_string_orig = ""
        # print(full_prompt)
        old_func_name = extract_function_name(input_code)
        total_tokens_used = 0
        for i in range(0, retries):
            try:
                response_string_orig,used_tokens = self.prompt(full_prompt)
                total_tokens_used += used_tokens
                # print(response_string)
                # with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                #    f.write(response_string)
                # with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "r") as f:
                #    response_string = f.read()
                response_dict, response_string = self.process_response(response_string_orig)
                improved_code, renaming_dict = split_response(response_dict)
                new_func_name = extract_function_name(improved_code)

                if new_func_name is None or new_func_name == "":
                    self.console.log(
                        f"[blue]{old_func_name}[/blue]:[orange3]Got invalid code from model, Retry  {i + 1}/{retries}[/orange3]")
                    continue

                if check_reverse_engineer_fail_happend(improved_code):
                    self.console.log(
                        f"[blue]{old_func_name}[/blue]:[orange3]Got reverse engineer fail from model, Retry  {i + 1}/{retries}[/orange3]")
                    continue

                if check_valid_code(improved_code):
                    improved_code = self.postprocess_code(improved_code)
                    if improved_code == input_code:
                        raise Exception("No change")
                    return improved_code, renaming_dict, total_tokens_used
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

            except json.JSONDecodeError as e:
                if i >= retries - 1:
                    with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp_response.json"), "w") as f:
                        f.write(response_string_orig)
                    raise MaxTriesExceeded("Max tries exceeded")
                if "Expecting value: line 1 column 1 (char 0)" in str(e) or "Unterminated string starting at:" in str(
                        e):
                    self.console.log(
                        f"[blue]{old_func_name}[/blue]:[orange3]Got incomplete response from model, Retry  {i + 1}/{retries}[/orange3]")
                    if i > 1:
                        continue

                    if len(full_prompt) // 2 > len(response_string) > len(full_prompt) // 4:
                        self.logger.warning(f"Response was: {response_string}")
                        self.logger.warning(f"Prompt was: {full_prompt}")
                    continue
            except APIConnectionError as e:

                if i >= retries - 1:
                    self.logger.exception(e)
                    raise OutOfTriesException(f"Out of tries! Is your HardLimit reached? Tokens used:{self.calc_used_tokens(full_prompt)}")

                if "Too Many Requests" in str(e):
                    self.console.log(
                        f"[blue]{old_func_name}[/blue]:[orange3]Got [red]Too many requests[/red] from model, will sleep now! Retry {i + 1}/{retries}[/orange3]")
                    time.sleep(120)
                    continue
            except InvalidResponseException as e:
                if i >= retries - 1:
                    raise MaxTriesExceeded("Max tries exceeded "+locator())
                continue
            except requests.exceptions.ChunkedEncodingError as e:
                if i >= retries - 1:
                    raise MaxTriesExceeded("Max tries exceeded "+locator())
                continue

            except TypeError as e:
                print(f"###### RESPONSE START @ {locator()} ######")
                print(response_string)
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
                    print(response_string)
                    print("###### RESPONSE END ######")
                    raise Exception(e)
        raise MaxTriesExceeded("Max tries exceeded")

    def testbench(self):

        with open(os.path.join(AI_MODULES_ROOT, "openAI_core", "temp", "temp.json"), "r") as f:
            response = f.read()
        response_dict, response_string = self.process_response(response)
        return response_dict, response_string

    def calc_used_tokens(self, function):
        if self.engine == PromptEngine.HYBRID:
            enc = tiktoken.encoding_for_model("gpt-4")
        elif "gpt-4" in self.engine.value or "gpt-3.5" in self.engine.value:
            enc = tiktoken.encoding_for_model("gpt-4")
        else:
            raise NotImplementedError(f"Engine {self.engine} not supported yet!"+locator())

        return int(len(enc.encode(function)))

    def add_missing_commas(self, response_string):
        """Adds missing commas to the response string"""
        response_string = response_string.replace('\"\n\"', '\",\n\"')
        response_string = response_string.replace('\"\n \"', '\",\n \"')
        response_string = response_string.replace('\"\n  \"', '\",\n  \"')
        response_string = response_string.replace('\"\n   \"', '\",\n   \"')
        response_string = response_string.replace('\"\n    \"', '\",\n    \"')

        return response_string
