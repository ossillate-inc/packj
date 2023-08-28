package osssanitizer.astgen_java.permission;

import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;

public class PermissionUtil {
	
	public static String PERM_JAVA_CODE_LOADING = "osssanitizer.permission.JAVA_CODE_LOADING";
	public static String PERM_NATIVE_CODE_LOADING = "osssanitizer.permission.NATIVE_CODE_LOADING";
	
	public static String[] JavaCodeLoadingClasses = new String[] {
		"java.lang.ClassLoader",
		"dalvik.system.BaseDexClassLoader",
		"java.security.SecureClassLoader",
		"dalvik.system.DexClassLoader",
		"dalvik.system.PathClassLoader",
		"java.net.URLClassLoader"
	};
	
	public static String[] NativeCodeLoadingMethods = new String[] {
		"<java.lang.System: void load(java.lang.String)>",
		"<java.lang.System: void loadLibrary(java.lang.String)>"
	};
	
	public static String[] UrlConstrucotrs = new String[] {
		"<java.net.URL: void <init>(java.lang.String)>",
		"<java.net.URL: void <init>(java.net.URL,java.lang.String)>",
		"<java.net.URL: void <init>(java.net.URL,java.lang.String,java.net.URLStreamHandler)>",
		"<java.net.URL: void <init>(java.net.URL,java.lang.String,java.lang.String)>",
		"<java.net.URL: void <init>(java.net.URL,java.lang.String,int,java.lang.String)>",
		"<java.net.URL: void <init>(java.net.URL,java.lang.String,int,java.lang.String,java.net.URLStreamHandler)>",
	};
	
	public static String[] SocketInput = new String[] {
		"<java.net.Socket: java.io.InputStream getInputStream()>",
	};
	
	public static String[] ServerSocketUsage = new String[] {
		"java.net.ServerSocket",
	};
	
	public static InvokeExpr getInvokeExpr(Unit unit) {
		InvokeExpr invokeExpr = null;
		if (unit instanceof AssignStmt) {
			AssignStmt assignStmt = (AssignStmt) unit;
			Value rValue = assignStmt.getRightOp();
			if (rValue instanceof InvokeExpr) {
				invokeExpr = (InvokeExpr) rValue;
			}
		} else if (unit instanceof InvokeStmt) {
			InvokeStmt invokeStmt = (InvokeStmt) unit;
			invokeExpr = invokeStmt.getInvokeExpr();
		}
		return invokeExpr;
	}
	
	public static void printPath(ArrayList<SootMethod> path) {
		StringBuilder sb = new StringBuilder();
		sb.append("Path: ");
		int length = path.size();
		for (int i = 0; i < length; i++) {
			SootMethod method = path.get(i);
			sb.append(method.getSignature());
			if (i < length - 1) {
				sb.append(" --> ");
			}
		}
		System.out.println(sb.toString());
	}
	
	public static String getPathStr(ArrayList<SootMethod> path) {
		StringBuilder sb = new StringBuilder();
		sb.append("Path: ");
		int length = path.size();
		for (int i = 0; i < length; i++) {
			SootMethod method = path.get(i);
			sb.append(method.getSignature());
			if (i < length - 1) {
				sb.append(" --> ");
			}
		}
		return sb.toString();
	}
	
	public static boolean isJavaCodeLoading(SootClass sootClass) {
		SootClass tmpClass = sootClass;
		while (tmpClass != null) {
			String className = tmpClass.getName();
			for (int i = 0; i < JavaCodeLoadingClasses.length; i++) {
				if (className.equals(JavaCodeLoadingClasses[i])) {
					return true;
				}
			}
			tmpClass = tmpClass.hasSuperclass() ? tmpClass.getSuperclass() : null;
		}
		return false;
	}
	
	public static boolean isNativeCodeLoading(SootMethod sootMethod) {
		String methSig = sootMethod.getSignature();
		for (int i = 0; i < NativeCodeLoadingMethods.length; i++) {
			if (methSig.equals(NativeCodeLoadingMethods[i])) {
				return true;
			}
		}
		return false;
	}
	
	public static boolean isUrlConstructor(String methodSig) {
		for (int i = 0; i < UrlConstrucotrs.length; i++) {
			if (methodSig.equals(UrlConstrucotrs[i])) {
				return true;
			}
		}
		return false;
	}
	
	public static Block getBlockContainsUnit(List<Block> blocks, Unit unit) {
		for (Block block : blocks) {
			Iterator<Unit> iter = block.iterator();
			while (iter.hasNext()) {
				Unit nextUnit = iter.next();
				if (nextUnit.equals(unit)) {
					return block;
				}
			}
		}
		return null;
	}
	
	public static Block getBlockContain(BlockGraph blockGraph, Unit unit) {
		List<Block> blocks = blockGraph.getBlocks();
		for (Block block : blocks) {
			Iterator<Unit> iter = block.iterator();
			while (iter.hasNext()) {
				Unit nextUnit = iter.next();
				if (nextUnit.equals(unit)) {
					return block;
				}
			}
		}
		return null;
	}
	
	public static String getDataDir() {
		return System.getProperty("user.dir") + File.separator + "data";
	}
	
	public static String getUserDir() {
		return System.getProperty("user.dir");
	}
}
