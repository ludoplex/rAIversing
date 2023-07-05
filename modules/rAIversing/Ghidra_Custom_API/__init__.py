import os

from rAIversing.Ghidra_Custom_API.HeadlessAnalyzer import HeadlessAnalyzerWrapper
from rAIversing.pathing import PROJECTS_ROOT, GHIDRA_SCRIPTS, BINARIES_ROOT
from rAIversing.utils import check_and_fix_bin_path, check_and_create_project_path, is_already_exported


def binary_to_c_code(binary_path, processor_id="", custom_headless_binary=None, project_location=None, project_name=None,debug=False,export_path=None,max_cpu=2):
    import_path = check_and_fix_bin_path(binary_path)
    project_name = os.path.basename(binary_path).replace(".", "_") if project_name is None else project_name
    project_location = f'{os.path.join(PROJECTS_ROOT, project_name)}' if project_location is None else project_location
    export_path = export_path if export_path is not None else project_location
    if is_already_exported(export_path, os.path.basename(binary_path)):
        return
    check_and_create_project_path(project_location)
    ah = HeadlessAnalyzerWrapper(custom_headless_binary)
    ah.import_file(import_path)
    ah.project_location(project_location) \
        .project_name(project_name) \
        .postScript(f'ExtractCcode.py "{export_path}"') \
        .scriptPath(f'{GHIDRA_SCRIPTS}') \
        .log(f'{PROJECTS_ROOT}/log') \
        .max_cpu(max_cpu)\
        .scriptlog(f'{PROJECTS_ROOT}/scriptlog')

    if processor_id != "":
        ah.processor(processor_id)
    if debug:
        ah.print()
    ah.run(debug)

def existing_project_to_c_code(project_location, binary_name=None, project_name=None,custom_headless_binary=None, export_with_stripped_names=False,debug=False,export_path=None,max_cpu=2):
    if project_name is None:
        project_name = os.path.basename(project_location)
    if binary_name is None:
        binary_name=project_name

    export_path = export_path if export_path is not None else project_location
    if is_already_exported(export_path, binary_name+"_stripped" if export_with_stripped_names else binary_name):
        return

    if export_with_stripped_names:
        export_with_stripped_names = "True"
    else:
        export_with_stripped_names = ""
    ah = HeadlessAnalyzerWrapper(custom_headless_binary)
    ah.project_location(f'{project_location}') \
        .project_name(project_name) \
        .postScript(f'ExtractCcode.py {export_path} {export_with_stripped_names}') \
        .process(binary_name) \
        .noanalysis()\
        .scriptPath(f'{GHIDRA_SCRIPTS}') \
        .log(f'{PROJECTS_ROOT}/log') \
        .scriptlog(f'{PROJECTS_ROOT}/scriptlog')\
        .max_cpu(max_cpu)
    if debug:
        ah.print()
    ah.run(debug)





def import_changes_to_ghidra_project(binary_path,custom_headless_binary=None, debug=False):
    import_path = check_and_fix_bin_path(binary_path)
    project_name = os.path.basename(binary_path).replace(".", "_")
    binary_name = os.path.basename(binary_path)
    ah = HeadlessAnalyzerWrapper(custom_headless_binary)
    ah.project_location(f'{os.path.join(PROJECTS_ROOT,project_name)}') \
        .project_name(project_name) \
        .scriptPath(f'{GHIDRA_SCRIPTS}') \
        .postScript(f'ImportChanges.py') \
        .process(binary_name) \
        .noanalysis() \
        .scriptlog(f'{PROJECTS_ROOT}/scriptlog')
    if debug:
        ah.print()
    ah.run(debug)

def import_changes_to_existing_project(project_location,binary_name=None,project_name=None,custom_headless_binary=None, debug=False):
    if project_name is None:
        project_name = os.path.basename(project_location)
    if binary_name is None:
        binary_name=project_name

    ah = HeadlessAnalyzerWrapper(custom_headless_binary)
    ah.project_location(f'{project_location}') \
        .project_name(project_name) \
        .scriptPath(f'{GHIDRA_SCRIPTS}') \
        .postScript(f'ImportChanges.py {project_location}') \
        .process(binary_name) \
        .noanalysis() \
        .scriptlog(f'{PROJECTS_ROOT}/scriptlog')

    if debug:
        ah.print()
    ah.run(debug)
