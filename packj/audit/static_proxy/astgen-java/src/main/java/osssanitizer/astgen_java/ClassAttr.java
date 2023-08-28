package osssanitizer.astgen_java;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.common.collect.Lists;

import osssanitizer.astgen_java.util.ClassSignaturesUtil;
import proto.ClassSig.ClassAttributeProto;
import proto.ClassSig.MethodAttributeProto;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Type;

public class ClassAttr {
	public String name = "";
	public String superClassName = "java.lang.Object";
	public String packageName = "";
	public String outerClassName = null;
	public String modifiers = "";
	// not used for now
	public boolean entryPoint = false;  

	public Set<String> interfaceClassNames = new HashSet<String>();
	public Set<String> sFieldStrs = new HashSet<String>();
	public Set<String> iFieldStrs = new HashSet<String>();
	// permission strings.
	public Set<String> permissionStrs = new HashSet<String>();
	public List<MethodAttributeProto> methodProtos = new ArrayList<MethodAttributeProto>();
	
	// deprecated, not used any more
	public Set<String> methodStrs = new HashSet<String>();
	// deprecated, not used any more
	public Set<String> sysCallStrs = new HashSet<String>();	
	
	public ClassAttr(SootClass sootClass) {
		name = sootClass.getName();
		if (sootClass.hasSuperclass())
			superClassName = sootClass.getSuperclass().getName();
		else
			System.out.println(sootClass.getName() + " doesn't have super class! This is weird!");
		packageName = sootClass.getPackageName();
		modifiers = Modifier.toString(sootClass.getModifiers());
		for (SootClass inter : sootClass.getInterfaces()) 
			interfaceClassNames.add(inter.getName());
		
		List<SootField> fields = Lists.newArrayList(sootClass.getFields());
		for (SootField field : fields) {
			String fieldStr = field.getType().toString();
			if (field.isStatic()) {
				sFieldStrs.add(fieldStr);
			} else {
				iFieldStrs.add(fieldStr);
			}
		}
		
		List<SootMethod> methods = sootClass.getMethods();
		for (SootMethod method : methods) {
			StringBuilder sb = new StringBuilder();
			String retStr = method.getReturnType().toString();
			sb.append(retStr);
			for (Type paramType : method.getParameterTypes()) {
				String paramStr = paramType.toString();
				sb.append("@");
				sb.append(paramStr);
			}
			methodStrs.add(sb.toString());
		}
	}
	
	public String getKey() {
		return name;
	}
	
	public boolean isEntryPoint() {
		return entryPoint;
	}

	public void setEntryPoint(boolean entryPoint) {
		this.entryPoint = entryPoint;
	}
	
	public void addSysCallStr(String sysCallStr) {
		sysCallStrs.add(sysCallStr);
	}
	
	public void addPermissionStr(String permission) {
		permissionStrs.add(permission);
	}
	
	public void addPermissionStr(Set<String> permissions) {
		permissionStrs.addAll(permissions);
	}
	
	public void addMethodProto(MethodAttributeProto proto) {
		methodProtos.add(proto);
	}
	
	public void setOuterClassName(String outerClass) {
		outerClassName = outerClass;
	}
	
	@Override
	public int hashCode() {
		return this.name.length();
	}

	@Override
	public boolean equals(Object object) {
		if (!(object instanceof ClassAttr)) {
			return false;
		}
		ClassAttr attr = (ClassAttr) object;
		return this.name.equals(attr.name);
	}	
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Class: ");
		sb.append(name);
		sb.append(" ");
		sb.append(superClassName);
		sb.append(" ");
		sb.append(packageName);
		sb.append(" ");
		
		sb.append(sFieldStrs.size());
		sb.append("#");
		for (String s : ClassSignaturesUtil.toSortedList(sFieldStrs)) {
			sb.append(s);
			sb.append("#");
		}
		sb.append(" ");
		
		sb.append(iFieldStrs.size());
		sb.append("#");
		for (String s : ClassSignaturesUtil.toSortedList(iFieldStrs)) {
			sb.append(s);
			sb.append("#");
		}
		sb.append(" ");
		
		sb.append(methodStrs.size());
		sb.append("#");
		for (String s : ClassSignaturesUtil.toSortedList(methodStrs)) {
			sb.append(s);
			sb.append("#");
		}
		sb.append(" ");
		
		sb.append(sysCallStrs.size());
		sb.append("#");
		for (String s : ClassSignaturesUtil.toSortedList(sysCallStrs)) {
			sb.append(s);
			sb.append("#");
		}
		
		sb.append(permissionStrs.size());
		sb.append("#");
		for (String s : ClassSignaturesUtil.toSortedList(permissionStrs)) {
			sb.append(s);
			sb.append("#");
		}
		
		return sb.toString();
	}
	
	public ClassAttributeProto toProto() {
		ClassAttributeProto.Builder ca = ClassAttributeProto.newBuilder();
		ca.setClassName(name);
		ca.setSuperClassName(superClassName);
		ca.addAllInterfaceClassNames(interfaceClassNames);
		ca.setPackageName(packageName);
		ca.setModifiers(modifiers);
		ca.setIsEntryPoint(entryPoint);
		if (outerClassName != null)
			ca.setOuterClassName(outerClassName);
		ca.addAllStaticFieldStrings(sFieldStrs);
		ca.addAllInstanceFieldStrings(iFieldStrs);
		ca.addAllPermissionStrings(permissionStrs);		
		ca.addAllMethods(methodProtos);
		return ca.build();
	}
}

