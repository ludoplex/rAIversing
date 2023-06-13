from enum import Enum


class PromptEngine(Enum):
    DEFAULT = "gpt-3.5-turbo"
    """Default Engine, currently gpt-3.5-turbo"""
    GPT_3_5_TURBO = "gpt-3.5-turbo"
    """GPT-3.5-turbo Engine, currently the default"""
    GPT_4 = "gpt-4"
    """GPT-4 only Engine (uses small and big context sizes when needed)"""
    HYBRID = "hybrid"
    """Hybrid Engine, used gpt-3.5-turbo for the first 3500 tokens, then GPT-4 until 6500 tokens, and GPT-4-32k until 30500 tokens"""

    def small(self):
        if self == PromptEngine.GPT_4:
            return PromptEngine.GPT_4.value
        elif self == PromptEngine.HYBRID:
            return PromptEngine.GPT_3_5_TURBO.value
        elif self == PromptEngine.GPT_3_5_TURBO or self == PromptEngine.DEFAULT:
            return PromptEngine.GPT_3_5_TURBO.value
        else:
            raise NotImplementedError("Small context size not implemented for this engine")

    def small_range(self):
        if self == PromptEngine.GPT_4:
            return range(0, 3501)
        elif self == PromptEngine.HYBRID:
            return range(0, 3501)
        elif self == PromptEngine.GPT_3_5_TURBO or self == PromptEngine.DEFAULT:
            return range(0, 3501)
        else:
            raise NotImplementedError("Small context size not implemented for this engine")

    def medium(self):
        if self == PromptEngine.GPT_4:
            return PromptEngine.GPT_4.value
        elif self == PromptEngine.HYBRID:
            return PromptEngine.GPT_3_5_TURBO.value + "-16k"
        elif self == PromptEngine.GPT_3_5_TURBO or self == PromptEngine.DEFAULT:
            return PromptEngine.GPT_3_5_TURBO.value + "-16k"
        else:
            raise NotImplementedError("Medium context size not implemented for this engine")

    def medium_range(self):
        if self == PromptEngine.GPT_4:
            return range(3501, 7001)
        elif self == PromptEngine.HYBRID:
            return range(3501, 15001)
        elif self == PromptEngine.GPT_3_5_TURBO or self == PromptEngine.DEFAULT:
            return range(3501, 15001)
        else:
            raise NotImplementedError("Medium context size not implemented for this engine")

    def large(self):
        if self == PromptEngine.GPT_4:
            return PromptEngine.GPT_4.value + "-32k-0613"
        elif self == PromptEngine.HYBRID:
            return PromptEngine.GPT_4.value + "-32k-0613"
        elif self == PromptEngine.GPT_3_5_TURBO or self == PromptEngine.DEFAULT:
            return PromptEngine.GPT_3_5_TURBO.value + "-16k"
        else:
            raise NotImplementedError("Large context size not implemented for this engine")

    def large_range(self):
        if self == PromptEngine.GPT_4:
            return range(7001, 31001)
        elif self == PromptEngine.HYBRID:
            return range(15001, 31001)
        elif self == PromptEngine.GPT_3_5_TURBO or self == PromptEngine.DEFAULT:
            return range(3501, 15001)  # Same as medium
        else:
            raise NotImplementedError("Large context size not implemented for this engine")
