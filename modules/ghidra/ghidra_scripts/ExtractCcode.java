// extract

import com.google.gson.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.util.ArrayList;
import java.lang.String;


public class ExtractCcode extends GhidraScript {

    @Override
    public void run() throws InvalidInputException, DuplicateNameException, IOException {
        FlatProgramAPI fpapi = new FlatProgramAPI(getState().getCurrentProgram());
        FlatDecompilerAPI fdapi = new FlatDecompilerAPI(fpapi);
        DecompileOptions options = new DecompileOptions();
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(options);
        ifc.openProgram(getState().getCurrentProgram());
        String[] args = getScriptArgs();
        String export_path = null;
        boolean exp_str = false;
        int limit = 700;
        if (args.length > 2) {
            export_path = args[0];
            exp_str = args[1].equals("True");
            try {
                limit = Integer.parseInt(args[2]);
            } catch (Exception e) {
                print("3rd argument is not an integer, continuing with a limit of 700");
            }
        } else if (args.length > 1) {
            export_path = args[0];
            try {
                limit = Integer.parseInt(args[1]);
            } catch (Exception e) {
                exp_str = args[1].equals("True");
            }
        } else if (args.length > 0) {
            export_path = args[0];
        }
        extract(export_path, exp_str, limit, fpapi, fdapi, monitor, ifc);
    }

    public void extract(String export_path, boolean export_with_stripped_names, int limit, FlatProgramAPI fpapi, FlatDecompilerAPI fdapi,
                        ConsoleTaskMonitor monitor, DecompInterface ifc)
            throws InvalidInputException, DuplicateNameException, IOException {
        String program_name = fpapi.getProgramFile().getName();
        GhidraState state = getState();
        Project project = state.getProject();
        ProjectLocator locator = project.getProjectData().getProjectLocator();
        ProjectManager projectMgr = project.getProjectManager();
        Project activeProject = projectMgr.getActiveProject();
        FunctionManager fm = currentProgram.getFunctionManager();
        ArrayList<Function> funcs = new ArrayList<>();
        fm.getFunctions(true).forEachRemaining(funcs::add);


        String replaced_pro_name = program_name.replace("_no_propagation", "").replace("_original", "");
        if (!export_path.contains(replaced_pro_name)) {
            export_path = Paths.get(export_path, replaced_pro_name).toString();
        }
        export_path = Paths.get(export_path.replace("\"", "")).toString();

        if (!Files.exists(Paths.get(export_path))) {
            Files.createDirectories(Paths.get(export_path));
        }

        JsonObject function_metadata = new JsonObject();

        String cCode = StandardCharsets.UTF_8.encode("").toString();

        if (funcs.size() > limit) {
            System.out.printf("More than %d functions in %s. Exiting!%n", limit,  program_name);
            String message = "More than "  + limit + " functions in " + program_name + ". Exiting!";
            Files.write(Paths.get(export_path, "not_extracted"), message.getBytes());
            print("#@#@#@#@#@#@#");
            return;
        }

        for (int i = 0; i < funcs.size(); i++) {
            Function func = funcs.get(i);
            String entrypoint = func.getEntryPoint().toString("0x");
            try {
                if (func_to_C(func, ifc, fdapi).contains("{\n                    /* WARNING: Bad instruction - Truncating control flow here */\n  halt_baddata();\n}")) {
                    continue;
                }
            } catch (Exception e) {
                System.out.println(e.toString());
                continue;
            }

            String function_name;
            if (export_with_stripped_names) {
                function_name = "FUN_" + entrypoint.replace("0x", "");
            } else {
                function_name = func.getName();
            }

            String code;
            if (export_with_stripped_names) {
                String original_name = func.getName();
                func.setName(function_name, SourceType.IMPORTED);
                ArrayList<Function> functions = new ArrayList<>();
                fm.getFunctions(true).forEachRemaining(functions::add);
                Function function = functions.get(i);
                code = func_to_C(function, ifc, fdapi);
                function.setName(original_name, SourceType.IMPORTED);
            } else {
                code = func_to_C(func, ifc, fdapi);
            }

            code = code.replace("/* WARNING: Unknown calling convention -- yet parameter storage is locked */", "");
            code = code.replace("/* WARNING: Control flow encountered bad instruction data */", "");
            code = code.replace("/* WARNING: Subroutine does not return */", "");
            code = code.replace("/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */", "");

            JsonObject func_name_json = new JsonObject();
            func_name_json.add("entrypoint", new JsonPrimitive(entrypoint));
            func_name_json.add("current_name", new JsonPrimitive(function_name));
            func_name_json.add("code", new JsonPrimitive(code));
            func_name_json.add("renaming", new JsonObject());
            func_name_json.add("calling", new JsonArray());
            func_name_json.add("called", new JsonArray());
            boolean improved = (!function_name.contains("FUN_")) | (!code.contains(function_name) & function_name.contains("FUN_"));
            func_name_json.add("improved", new JsonPrimitive(improved));
            func_name_json.add("skipped", new JsonPrimitive(false));
            func_name_json.add("imported", new JsonPrimitive(false));
            func_name_json.add("tags", new JsonArray());

            for (Function calling : func.getCallingFunctions(getMonitor())) {
                JsonArray jelem = func_name_json.getAsJsonArray("calling");
                jelem.add(new JsonPrimitive(calling.getName()));
            }
            for (Function called : func.getCalledFunctions(getMonitor())) {
                JsonArray jelem = func_name_json.getAsJsonArray("called");
                jelem.add(new JsonPrimitive(called.getName()));
            }

            function_metadata.add(function_name, func_name_json);

            cCode += StandardCharsets.UTF_8.decode(StandardCharsets.UTF_8.encode("\n////>>" + func.getEntryPoint().toString("0x") + ">>" + function_name + ">>////\n"));
            cCode += StandardCharsets.UTF_8.decode(StandardCharsets.UTF_8.encode(code));

        }

        program_name = fpapi.getCurrentProgram().toString().split(" ")[0].replace(".", "_");

        if (!export_with_stripped_names) {
            Path filepath = Paths.get(export_path, program_name+".c");
            Files.write(filepath, cCode.getBytes());
        }

        JsonObject save_file = new JsonObject();
        save_file.add("functions", function_metadata);
        save_file.add("layers", new JsonArray());
        save_file.add("locked_functions", new JsonArray());
        save_file.add("used_tokens", new JsonPrimitive(0));

        if (export_with_stripped_names) {
            program_name += "_stripped";
        }

        if (!Files.exists(Paths.get(export_path, program_name+".json"))) {
            Path jspath = Paths.get(export_path, program_name+".json");
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            String pretty_sf = gson.toJson(save_file);
            Files.write(jspath, pretty_sf.getBytes());
        }
    }

    public String func_to_C(Function func, DecompInterface ifc, FlatDecompilerAPI fdapi) {
        String res;
        try {
            res = ifc.decompileFunction(func, 0, new ConsoleTaskMonitor()).getDecompiledFunction().getC();
        } catch (Exception e) {
            try {
                res = StandardCharsets.UTF_8.decode(StandardCharsets.UTF_8.encode(fdapi.decompile(func))).toString();
            } catch (Exception e1) {
                res = "{\n                    /* WARNING: Bad instruction - Truncating control flow here */\n  halt_baddata();\n}";
            }
        }
        return res;
    }

}

