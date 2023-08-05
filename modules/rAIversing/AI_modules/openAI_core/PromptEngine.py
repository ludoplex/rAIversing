from enum import Enum


small_threshold = 3301
medium_threshold = 6901
medium_large_threshold = 14901
large_threshold = 30401


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
        elif self in [PromptEngine.GPT_3_5_TURBO, PromptEngine.DEFAULT]:
            return PromptEngine.GPT_3_5_TURBO.value
        else:
            raise NotImplementedError("Small context size not implemented for this engine")

    def small_range(self):
        if self == PromptEngine.GPT_4:
            return range(0, small_threshold)
        elif self == PromptEngine.HYBRID:
            return range(0, small_threshold)
        elif self in [PromptEngine.GPT_3_5_TURBO, PromptEngine.DEFAULT]:
            return range(0, small_threshold)
        else:
            raise NotImplementedError("Small context size not implemented for this engine")

    def medium(self):
        if self == PromptEngine.GPT_4:
            return PromptEngine.GPT_4.value
        elif self == PromptEngine.HYBRID:
            return f"{PromptEngine.GPT_3_5_TURBO.value}-16k"
        elif self in [PromptEngine.GPT_3_5_TURBO, PromptEngine.DEFAULT]:
            return f"{PromptEngine.GPT_3_5_TURBO.value}-16k"
        else:
            raise NotImplementedError("Medium context size not implemented for this engine")

    def medium_range(self):
        if self == PromptEngine.GPT_4:
            return range(small_threshold, medium_threshold)
        elif self == PromptEngine.HYBRID:
            return range(small_threshold, medium_large_threshold)
        elif self in [PromptEngine.GPT_3_5_TURBO, PromptEngine.DEFAULT]:
            return range(small_threshold, medium_large_threshold)
        else:
            raise NotImplementedError("Medium context size not implemented for this engine")

    def large(self):
        if self == PromptEngine.GPT_4:
            return PromptEngine.GPT_4.value #+ "-32k-0613"
        elif self == PromptEngine.HYBRID:
            return PromptEngine.GPT_4.value #+ "-32k-0613"
        elif self in [PromptEngine.GPT_3_5_TURBO, PromptEngine.DEFAULT]:
            return f"{PromptEngine.GPT_3_5_TURBO.value}-16k"
        else:
            raise NotImplementedError("Large context size not implemented for this engine")

    def large_range(self):
        if self == PromptEngine.GPT_4:
            return range(small_threshold, medium_threshold)
            #return range(7001, 31001)
        elif self == PromptEngine.HYBRID:
            return range(medium_large_threshold, large_threshold)
        elif self in [PromptEngine.GPT_3_5_TURBO, PromptEngine.DEFAULT]:
            return range(small_threshold, medium_large_threshold)  # Same as medium
        else:
            raise NotImplementedError("Large context size not implemented for this engine")
