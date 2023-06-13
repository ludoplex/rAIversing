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
