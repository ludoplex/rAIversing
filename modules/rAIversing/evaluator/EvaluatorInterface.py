class EvaluatorInterface:

    def __init__(self,ai_modules,source_dirs,runs=1,pool_size=1):
        self.ai_modules = ai_modules
        self.source_dirs = source_dirs
        self.runs = runs
        self.pool_size = pool_size

    def evaluate(self):
        """TODO: Docstring for evaluate."""
        pass




