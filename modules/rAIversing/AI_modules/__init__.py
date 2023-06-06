class AiModuleInterface:


    def prompt(self, prompt):  # type: (str) -> str
        """Prompts the model and returns the result"""
        pass

    def prompt_with_renaming(self, input_code, retries):  # type: (str,int) -> (str, dict)
        """Prompts the model and returns the resulting code and a dict of renamed Names"""
        pass

    def assemble_prompt(self, input_code):
        """Assembles the prompt for the model"""
        pass

    def calc_used_tokens(self, input_code):
        """Calculates the number of tokens used by the input code"""
        pass

    def get_model_name(self):
        """Returns the name of the model"""
        pass

    def get_max_tokens(self):
        """Returns the maximum number of tokens the model can handle"""
        pass