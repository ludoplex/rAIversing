import os

from rAIversing.Ghidra_Custom_API.HeadlessAnalyzer import HeadlessAnalyzerWrapper
from rAIversing.pathing import PROJECTS_ROOT, GHIDRA_SCRIPTS, BINARIES_ROOT
from rAIversing.utils import check_and_fix_bin_path, check_and_create_project_path, is_already_exported


def folder_processor(folder_path, language_id="", cspec="", custom_headless_binary=None, project_location=None,
                     project_name=None, debug=False, export_path=None, max_cpu=-1, process_only=False,
                     import_only=False):
    """
    Create a command to be executed to process a folder containing binaries with Ghidra.
    Used by the Evaluation module.
    :type folder_path: str
    :param folder_path: The path to the folder containing the binaries to be processed
    :param language_id: Optional language id to be used by Ghidra
    :param cspec: Optional compiler id to be used by Ghidra
    :param custom_headless_binary: Optional path to a custom analyzeHeadless binary location
    :param project_location: Optional path to the project location (defaults to projects/{project_name})
    :param project_name: Optional name of the project (defaults to the name of the folder containing the binaries)
    :param debug: Optional flag to enable debug mode
    :param export_path: Optional path to the folder where the exported files will be saved (defaults to project_location)
    :param max_cpu: Optional maximum number of cpus to be used by Ghidra (defaults to -1 which means no -max-cpu flag will be used)
    :param process_only: Flag to indicate that the binaries should not be imported (again), only processed
    :param import_only: Flag to indicate that the binaries should not be processed, only imported
    :return: Command to be executed
    """
    project_name = project_name if project_name else os.path.basename(folder_path).replace(".", "_")
    project_location = project_location if project_location else f'{os.path.join(PROJECTS_ROOT, project_name)}'
    export_path = export_path if export_path else project_location
    if is_already_exported(export_path, os.path.basename(folder_path)):
        return
    check_and_create_project_path(project_location)
    ah = HeadlessAnalyzerWrapper(custom_headless_binary)
    if import_only and process_only:
        raise Exception("import_only and process_only cannot be both true")

    if not process_only:
        for thing in os.listdir(folder_path):
            if not os.path.isfile(os.path.join(folder_path, thing)):
                ah.add_import_file(os.path.join(folder_path, thing))
    else:
        ah.process("")
        ah.noanalysis()
    ah.recursive()
    if not import_only and process_only:
        ah.postScript(f'ExtractCcode.java {export_path}')
    ah.project_location(project_location) \
        .project_name(project_name) \
        .scriptPath(f'{GHIDRA_SCRIPTS}') \
        .log(f'{PROJECTS_ROOT}/log') \
        .max_cpu(max_cpu) \
        .scriptlog(f'{PROJECTS_ROOT}/scriptlog')
    if language_id != "":
        ah.processor(language_id)
    if cspec != "":
        ah.cspec(cspec)
    if debug:
        ah.print()
    return ah.get_command()


def binary_to_c_code(binary_path, language_id="", compiler_id="", custom_headless_binary=None, project_location=None,
                     project_name=None, debug=False, export_path=None, max_cpu=2):
    """
    Export a binary to C code using Ghidra.
    :param binary_path: Path to the binary to be exported
    :param language_id: Optional language id to be used by Ghidra
    :param compiler_id: Optional compiler id to be used by Ghidra
    :param custom_headless_binary: Optional path to a custom analyzeHeadless binary location
    :param project_location: Optional path to the project location (defaults to PROJECTS_ROOT/{project_name})
    :param project_name: Optional name of the project (defaults to the name of the binary)
    :param debug: Optional flag to enable debug mode
    :param export_path: Optional path to the folder where the exported files will be saved (defaults to project_location)
    :param max_cpu: Optional maximum number of cpus to be used by Ghidra (defaults to 2)
    """
    import_path = check_and_fix_bin_path(binary_path)
    project_name = project_name if project_name else os.path.basename(binary_path).replace(".", "_")
    project_location = project_location if project_location else f'{os.path.join(PROJECTS_ROOT, project_name)}'
    export_path = export_path if export_path else project_location
    if is_already_exported(export_path, os.path.basename(binary_path)):
        return
    check_and_create_project_path(project_location)
    ah = HeadlessAnalyzerWrapper(custom_headless_binary)
    ah.import_file(import_path)
    ah.project_location(project_location) \
        .project_name(project_name) \
        .postScript(f'ExtractCcode.java "{export_path}"') \
        .scriptPath(f'{GHIDRA_SCRIPTS}') \
        .log(f'{PROJECTS_ROOT}/log') \
        .max_cpu(max_cpu) \
        .scriptlog(f'{PROJECTS_ROOT}/scriptlog')
    if language_id != "":
        ah.processor(language_id)
    if compiler_id != "":
        ah.cspec(compiler_id)
    if debug:
        ah.print()
    ah.run(debug)


def existing_project_to_c_code(project_location, binary_name=None, project_name=None, custom_headless_binary=None,
                               export_with_stripped_names=False, debug=False, export_path=None, max_cpu=2,
                               folder_path=None):
    if project_name is None:
        project_name = os.path.basename(project_location)
    if binary_name is None:
        binary_name = project_name

    export_path = export_path if export_path is not None else project_location
    if is_already_exported(export_path, binary_name + "_stripped" if export_with_stripped_names else binary_name):
        return
    if export_with_stripped_names:
        export_with_stripped_names = "True"
    else:
        export_with_stripped_names = ""
    ah = HeadlessAnalyzerWrapper(custom_headless_binary)
    ah.project_location(f'{project_location}') \
        .project_name(project_name) \
        .postScript(f'ExtractCcode.java {export_path} {export_with_stripped_names}') \
        .process(binary_name) \
        .noanalysis() \
        .scriptPath(f'{GHIDRA_SCRIPTS}') \
        .log(f'{PROJECTS_ROOT}/log') \
        .scriptlog(f'{PROJECTS_ROOT}/scriptlog') \
        .folder_path(folder_path) \
        .max_cpu(max_cpu)

    if debug:
        ah.print()
    ah.run(debug)


def import_changes_to_existing_project(project_location, binary_name=None, project_name=None,
                                       custom_headless_binary=None, debug=False):
    if project_name is None:
        project_name = os.path.basename(project_location)
    if binary_name is None:
        binary_name = project_name

    ah = HeadlessAnalyzerWrapper(custom_headless_binary)
    ah.project_location(f'{project_location}') \
        .project_name(project_name) \
        .scriptPath(f'{GHIDRA_SCRIPTS}') \
        .postScript(f'ImportChanges.java {project_location}') \
        .process(binary_name) \
        .noanalysis() \
        .scriptlog(f'{PROJECTS_ROOT}/scriptlog')

    if debug:
        ah.print()
    ah.run(debug)
