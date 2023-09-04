package osssanitizer.astgen_java.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;

import osssanitizer.astgen_java.ClassesPair;
import soot.SootClass;
import soot.Type;

public class ClassSignaturesUtil {
	
	public static ClassesPair getClassesPair(Map<String, ClassesPair> pairs, String classname1, String classname2,
			boolean classname2IsApplicationClass) {
		String key = classname1 + "," + classname2;
		if (pairs.containsKey(key)) {
			return pairs.get(key);
		} else {
			ClassesPair pair = new ClassesPair(classname1, classname2, classname2IsApplicationClass);
			pairs.put(key, pair);
			return pair;
		}
	}
	
	public static void updateClassesPair(ConcurrentMap<String, ClassesPair> pairs, String classname1, String classname2,
			boolean classname2IsApplicationClass, int relationType) {
		updateClassesPair(pairs, classname1, classname2, classname2IsApplicationClass, relationType, null);
	}
	
	public static void updateClassesPair(ConcurrentMap<String, ClassesPair> pairs, String classname1, String classname2,
			boolean classname2IsApplicationClass, int relationType, String permission) {
		String key = classname1 + "," + classname2;
		pairs.putIfAbsent(key, new ClassesPair(classname1, classname2, classname2IsApplicationClass));
		pairs.computeIfPresent(key, (k, v) -> {
			v.relationNums[relationType]++;
			if (permission != null) v.addPermission(permission);
			return v;
		});
	}
	
	public static boolean isTypeExist(Map<String, SootClass> appClasses, Type type) {
		return appClasses.containsKey(type.toString());
	}
	
	public static SootClass getTypeClass(Map<String, SootClass> appClasses, Type type) {
		if (appClasses.containsKey(type.toString()))
			return appClasses.get(type.toString());
		return null;
	}
	
	public static boolean isTypeExist(Map<String, SootClass> appClasses, String classname) {
		return (appClasses.containsKey(classname));
	}
	
	
	public static SootClass getTypeClass(Map<String, SootClass> appClasses, String classname) {
		if (appClasses.containsKey(classname))
			return appClasses.get(classname);
		return null;
	}
	
	public static List<String> toSortedList(Set<String> in) {
		ArrayList<String> inList = new ArrayList<String>(in);
		Collections.sort(inList);
		return inList;
	}
}
