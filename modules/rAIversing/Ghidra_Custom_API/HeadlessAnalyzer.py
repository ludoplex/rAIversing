import os, sys
import subprocess

from rAIversing.pathing import *


# Headless Analyzer Usage: analyzeHeadless
#           <project_location> <project_name>[/<folder_path>]
#             | ghidra://<server>[:<port>]/<repository_name>[/<folder_path>]
#           [[-import [<directory>|<file>]+] | [-process [<project_file>]]]
#           [-preScript <ScriptName>]
#           [-postScript <ScriptName>]
#           [-scriptPath "<path1>[;<path2>...]"]
#           [-propertiesPath "<path1>[;<path2>...]"]
#           [-scriptlog <path to script log file>]
#           [-log <path to log file>]
#           [-overwrite]
#           [-readOnly]
#           [-deleteProject]
#           [-processor <languageID>]
#           [-cspec <compilerSpecID>]
#           [-analysisTimeoutPerFile <timeout in seconds>]
#           [-max-cpu <max cpu cores to use>]
#           [-loader <desired loader name>]

class HeadlessAnalyzerWrapper:

    def __init__(self, analyzeHeadlessBinary=None):
        self.__analyzeHeadlessBinary__ = analyzeHeadlessBinary if analyzeHeadlessBinary is not None else GHIDRA_HEADLESS_BINARY
        self.__command__ = ""
        self.__import_file__ = ""
        self.__process__ = ""
        self.__project_location__ = ""
        self.__project_name__ = ""
        self.__folder_path__ = ""
        self.__preScript__ = ""
        self.__postScript__ = ""
        self.__scriptPath__ = ""
        self.__propertiesPath__ = ""
        self.__scriptlog__ = ""
        self.__log__ = ""
        self.__overwrite__ = ""
        self.__readOnly__ = ""
        self.__deleteProject__ = ""
        self.__processor__ = ""
        self.__cspec__ = ""
        self.__analysisTimeoutPerFile__ = ""
        self.__max_cpu__ = ""
        self.__loader__ = ""
        self.__noanalysis__ = ""
        self.__recursive__ = ""

        if not os.path.exists(self.__analyzeHeadlessBinary__):
            raise FileNotFoundError(f'analyzeHeadlessBinary not found: {self.__analyzeHeadlessBinary__}')
        if not os.access(self.__analyzeHeadlessBinary__, os.X_OK):
            raise PermissionError(f'analyzeHeadlessBinary is not executable: {self.__analyzeHeadlessBinary__}\n run "chmod +x {self.__analyzeHeadlessBinary__}"')

    def noanalysis(self):
        self.__noanalysis__ = ' -noanalysis'
        return self

    def recursive(self):
        self.__recursive__ = ' -recursive'
        return self

    def process(self, file):
        self.__process__ = f' -process {file}'
        return self

    def import_file(self, file_path):
        self.__import_file__ = f' -import {file_path}'
        return self

    def add_import_file(self, file_path):
        self.__import_file__ += f' -import {file_path}'
        return self

    def project_location(self, project_location):
        self.__project_location__ = f'{project_location}'
        return self

    def project_name(self, project_name):
        self.__project_name__ = f'{project_name}'
        return self

    def folder_path(self, folder_path):
        self.__folder_path__ = f'{folder_path}'
        return self

    def preScript(self, preScript):
        self.__preScript__ = f' -preScript {preScript}'
        return self

    def postScript(self, postScript):
        self.__postScript__ = f' -postScript {postScript}'
        return self

    def scriptPath(self, scriptPath):
        self.__scriptPath__ = f' -scriptPath {scriptPath}'
        return self

    def propertiesPath(self, propertiesPath):
        self.__propertiesPath__ = f' -propertiesPath {propertiesPath}'
        return self

    def scriptlog(self, scriptlog):
        self.__scriptlog__ = f' -scriptlog {scriptlog}'
        return self

    def log(self, log):
        self.__log__ = f' -log {log}'
        return self

    def overwrite(self):
        self.__overwrite__ = ' -overwrite'
        return self

    def readOnly(self):
        self.__readOnly__ = ' -readOnly'
        return self

    def deleteProject(self):
        self.__deleteProject__ = ' -deleteProject'
        return self

    def processor(self, processor):
        self.__processor__ = f' -processor {processor}'
        return self

    def cspec(self, cspec):
        self.__cspec__ = f' -cspec {cspec}'
        return self

    def analysisTimeoutPerFile(self, timeoutInSeconds):
        self.__analysisTimeoutPerFile__ = f' -analysisTimeoutPerFile {timeoutInSeconds}'
        return self

    def max_cpu(self, max_cpu_cores):
        self.__max_cpu__ = f' -max-cpu {max_cpu_cores}'
        return self

    def loader(self, loader):
        self.__loader__ = f' -loader {loader}'
        return self

    def __prepare_project_location__(self):
        if not os.path.exists(os.path.join(self.__project_location__, self.__project_name__.strip())):
            os.mkdir(os.path.join(self.__project_location__, self.__project_name__.strip()).strip())

    def __build__(self):
        if self.__folder_path__ != "":
            path = os.path.join(self.__project_name__, self.__folder_path__)
        else:
            path = self.__project_name__
        self.__command__ = f"{self.__analyzeHeadlessBinary__}" \
                           f" {self.__project_location__} {path}" \
                           f"{self.__import_file__}" \
                           f"{self.__preScript__}" \
                           f"{self.__postScript__}" \
                           f"{self.__scriptPath__}" \
                           f"{self.__process__}" \
                           f"{self.__recursive__}" \
                           f"{self.__propertiesPath__}" \
                           f"{self.__scriptlog__}" \
                           f"{self.__log__}" \
                           f"{self.__overwrite__}" \
                           f"{self.__readOnly__}" \
                           f"{self.__deleteProject__}" \
                           f"{self.__processor__}" \
                           f"{self.__cspec__}" \
                           f"{self.__analysisTimeoutPerFile__}" \
                           f"{self.__max_cpu__}" \
                           f"{self.__noanalysis__}" \
                           f"{self.__loader__}"

        return self

    def print(self):
        self.__build__()
        print(self.__command__)

    def get_command(self):
        self.__build__()
        return self.__command__
    def run(self, debug=False):
        self.__build__()
        if debug:
            os.system(self.__command__)
        else:
            output = subprocess.check_output(self.__command__, shell=True, stderr=subprocess.STDOUT)
