package osssanitizer.astgen_java.permission;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

public class PSCout {
	public HashSet<String> criticalApis = null;
	public HashMap<String, ArrayList<String>> permission2Apis = null;
	public HashMap<String, ArrayList<String>> intent2Permissions = null;
	
	public PSCout(String apiMappingFilePath, String intentMappingFilePath) {
		this.criticalApis = new HashSet<String>();
		this.permission2Apis = new HashMap<String, ArrayList<String>>();
		this.intent2Permissions = new HashMap<String, ArrayList<String>>();
		initApiMapping(apiMappingFilePath);
		initIntentMapping(intentMappingFilePath);
	}
	
	
	public void initApiMapping(String filepath) {
		try {
			BufferedReader bufferedReader = new BufferedReader(new FileReader(new File(filepath)));
			String line = null;
			String currPermission = null;
			while ((line = bufferedReader.readLine()) != null) {
				if (line.startsWith("Permission:")) {
					currPermission = line.split(":")[1];
					permission2Apis.put(currPermission, new ArrayList<String>());
					continue;
				}
				
				if (line.endsWith("Callers:\n")) {
					continue;
				}
				
				if (line.startsWith("<")) {
					String className = line.split(":")[0].split("<")[1];
					String methodName = line.split(" ")[2].split("\\(")[0];
					String api = className + "." + methodName;
					criticalApis.add(api);
					ArrayList<String> apis = permission2Apis.get(currPermission);
					if (!apis.contains(api)) {
						apis.add(api);
					}
				}
			}
			bufferedReader.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void initIntentMapping(String filepath) {
		try {
			BufferedReader bufferedReader = new BufferedReader(new FileReader(new File(filepath)));
			String line = null;
			while ((line = bufferedReader.readLine()) != null) {
				String intent = line.split(" ")[0];
				String permission = line.split(" ")[1];
				if (!this.intent2Permissions.keySet().contains(intent)) {
					ArrayList<String> permissions = new ArrayList<String>();
					permissions.add(permission);
					this.intent2Permissions.put(intent, permissions);
				} else {
					ArrayList<String> permissions = this.intent2Permissions.get(intent);
					if (!permissions.contains(permission)) {
						permissions.add(permission);
					}
				}
			}
			bufferedReader.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public boolean isCriticalApi(String api) {
		if (criticalApis.contains(api)) {
			return true;
		} else {
			return false;
		}
	}
	
	public String getApiPermission(String api) {
		for (String permission : this.permission2Apis.keySet()) {
			ArrayList<String> apis = this.permission2Apis.get(permission);
			if (apis.contains(api)) {
				return permission;
			}
		}
		return null;
	}
	
	public ArrayList<String> getIntentPermission(String intent) {
		return this.intent2Permissions.get(intent);
	}
}
