import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.ConsoleTaskMonitor;


import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class ImportChanges extends GhidraScript {

    @Override
    public void run() throws Exception {
		FlatProgramAPI fpapi = new FlatProgramAPI(getState().getCurrentProgram());
		FlatDecompilerAPI fdapi = new FlatDecompilerAPI(fpapi);
		DecompileOptions options = new DecompileOptions();
		ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);
		ifc.openProgram(getState().getCurrentProgram());
		String[] args = getScriptArgs();
		if (args.length > 0) {
			importChanges(args[0], fpapi, ifc, monitor);
		} else {
			importChanges(fpapi, ifc, monitor);
		}
	}

	public void importChanges(FlatProgramAPI fpapi, DecompInterface ifc, ConsoleTaskMonitor monitor) throws InvalidInputException, DuplicateNameException, IOException {
		importChanges(null, fpapi, ifc, monitor);
	}

	public void importChanges(String js_fp, FlatProgramAPI fpapi, DecompInterface ifc, ConsoleTaskMonitor monitor) throws IOException, InvalidInputException, DuplicateNameException {
		GhidraState state = getState();
		Project project = state.getProject();
		ProjectLocator locator = project.getProjectData().getProjectLocator();
		FunctionManager fm = currentProgram.getFunctionManager();
		ArrayList<Function> funcs = new ArrayList<>();
		fm.getFunctions(true).forEachRemaining(funcs::add);

		String programe_name = fpapi.getCurrentProgram().toString().split(" ")[0].replace(".", "_");
		if (js_fp == null) {
			//js_fp = Paths.get(Pathing.PROJECTS_ROOT.toString(), programe_name, programe_name+".json").toString();
			;
		} else {
		    js_fp = Paths.get(js_fp, programe_name+".json").toString();
		}


		String read = Files.readString(Paths.get(js_fp));
		JsonObject save_file = new Gson().fromJson(read, JsonObject.class);
		JsonObject functions_dict;
		if (save_file.keySet().contains("functions")) {
			functions_dict = save_file.getAsJsonObject("functions");
		} else {
			functions_dict = save_file;
		}

		HashMap<String, String> current_lookup = new HashMap<>();
		HashMap<String, String> original_lookup = new HashMap<>();
		for (String function_name : functions_dict.keySet()) {
			JsonObject data = functions_dict.getAsJsonObject(function_name);
			String current_name = data.get("current_name").getAsString();
			current_lookup.put(function_name, current_name);
			original_lookup.put(current_name, function_name);
		}

		for (Function func : funcs) {
			String func_name = func.getName();

			if (!current_lookup.containsKey(func_name)) {
				if (original_lookup.containsKey(func_name)) {
					func_name = original_lookup.get(func_name);
				}
			}

			if (functions_dict.has(func_name)) {
				JsonObject function_data = functions_dict.getAsJsonObject(func_name);
				JsonObject renaming_dict = function_data.getAsJsonObject("renaming");
				String new_name = function_data.get("current_name").getAsString();

				if (function_data.get("skipped").getAsBoolean() | function_data.has("imported") & function_data.get("imported").getAsBoolean()) {
					continue;
				}

				if (!function_data.get("improved").getAsBoolean()) {
					continue;
				}

				if (!func.getName().equals(new_name)) {
					func.setName(new_name, SourceType.IMPORTED);
					System.out.println("Renaming" + func_name + " to " + new_name);
				}

				HighFunction hf = get_high_function(func, ifc, monitor);
				Iterator<HighSymbol> symbols = get_function_symbols(func, ifc, monitor);

				for (Iterator<HighSymbol> it = symbols; it.hasNext(); ) {
					HighSymbol high_symbol = it.next();
					String symname = high_symbol.getName();
					if (renaming_dict.has(symname)) {
						new_name = renaming_dict.get(symname).getAsString();
						if (new_name.equals("") | new_name.equals(symname) | new_name.contains(" ") | new_name.contains(",")) {
							continue;
						}
						Symbol symbol = high_symbol.getSymbol();
						if (symbol == null) {
							continue;
						}
						try {
							symbol.setName(new_name, SourceType.IMPORTED);
						} catch (DuplicateNameException dne) {
							new_name = new_name + "_";
							try {
								symbol.setName(new_name, SourceType.IMPORTED);
							} catch (DuplicateNameException dne2) {
								continue;
							}
						} catch (Exception e) {
							if (e.toString().contains("NoneType")) {
								continue;
							}
							System.out.println("Error while renaming " + symname + " in function " + func_name);
							System.out.println(e.toString());
							continue;
						}
						}
					HighFunctionDBUtil.commitLocalNamesToDatabase(hf, SourceType.IMPORTED);
					HighFunctionDBUtil.commitParamsToDatabase(hf, true, SourceType.IMPORTED);

					ArrayList<Variable> vars_params = new ArrayList<>(Arrays.stream(func.getAllVariables()).toList());
					vars_params.addAll(Arrays.stream(func.getParameters()).toList());
					for (Variable var : vars_params) {
						String var_name = var.getName();
						if (renaming_dict.has(var_name)) {
							new_name = renaming_dict.get(var_name).getAsString();
							if (new_name.equals("") | new_name.equals(var_name) | new_name.contains(" ") | new_name.contains(",")) {
								continue;
							}
							try {
								var.setName(new_name, SourceType.IMPORTED);
							} catch (DuplicateNameException dn) {
								new_name = new_name  + "_";
								try {
									var.setName(new_name, SourceType.IMPORTED);
								} catch (DuplicateNameException dn2) {
									continue;
								}
							}
						}
					}
					functions_dict.get(func_name).getAsJsonObject().addProperty("imported", true);
				}
			}
		}

		for (String func_name : functions_dict.keySet()) {
			JsonObject data = functions_dict.getAsJsonObject(func_name);
			if (!data.get("imported").getAsBoolean()) {
				functions_dict.getAsJsonObject(func_name).addProperty("imported", true);
			}
		}

		if (save_file.keySet().contains("functions")) {
			save_file.add("functions", functions_dict);
		} else {
			save_file = functions_dict;
		}
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		String pretty_sf = gson.toJson(save_file);
		Files.write(Paths.get(js_fp), pretty_sf.getBytes());
	}

		public HighFunction get_high_function(Function func, DecompInterface ifc, ConsoleTaskMonitor monitor) {
			DecompileResults res = ifc.decompileFunction(func, 60, monitor);
			HighFunction high = res.getHighFunction();
			return high;
		}

		public Iterator<HighSymbol> get_function_symbols (Function func, DecompInterface ifc, ConsoleTaskMonitor monitor) {
			HighFunction hf = get_high_function(func, ifc, monitor);
			LocalSymbolMap lsm = hf.getLocalSymbolMap();
			return lsm.getSymbols();
		}
}