package osssanitizer.astgen_java;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.Lists;

import osssanitizer.astgen_java.permission.PSCout;
import osssanitizer.astgen_java.permission.PermissionUtil;
import osssanitizer.astgen_java.util.BasicBlockUtil;
import osssanitizer.astgen_java.util.ClassSignaturesUtil;
import osssanitizer.astgen_java.util.ProtoBufferUtil;
import osssanitizer.astgen_java.util.SootConfigUtil;
import proto.ClassSig.BasicBlockProto;
import proto.ClassSig.MethodAttributeProto;
import proto.ClassSig.PkgClassMethodResult;
import proto.Ast.AstLookupConfig;
import proto.Ast.AstNode;
import proto.Ast.Language;
import proto.Ast.FileInfo;
import proto.Ast.PkgAstResult;
import proto.Ast.PkgAstResults;
import proto.Ast.SourceLocation;
import proto.Ast.SourceRange;
import heros.solver.CountingThreadPoolExecutor;
import soot.ArrayType;
import soot.Body;
import soot.BodyTransformer;
import soot.Local;
import soot.Modifier;
import soot.PackManager;
import soot.PatchingChain;
import soot.Scene;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Transform;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.ArrayRef;
import soot.jimple.AssignStmt;
import soot.jimple.CastExpr;
import soot.jimple.Expr;
import soot.jimple.InstanceFieldRef;
import soot.jimple.InstanceOfExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.NewArrayExpr;
import soot.jimple.NewExpr;
import soot.jimple.NewMultiArrayExpr;
import soot.jimple.ReturnStmt;
import soot.jimple.StaticFieldRef;
import soot.jimple.StringConstant;
import soot.toolkits.graph.Block;
import soot.util.Chain;

/**
 * Extract signatures for the given input classes. The signatures includes two parts, 
 * (1) first part is the analysis of application classes
 * (2) second part is the relationship between application classes and all other classes
 * (app & framework classes)
 * 
 * @author ruian
 */
public class ClassSignatures {
	public org.apache.commons.cli.Options options = null;
	private PSCout psCout = null;
	private AstLookupConfig config = null;
	private SootConfigUtil sootConfig = null;
	
	public ClassSignatures(AstLookupConfig configpb, SootConfigUtil sootConfigUtil) {
		config = configpb;
		sootConfig = sootConfigUtil;
		this.setSootOptions(sootConfig);
	}
	
	// The output
	// maps class name to ClassAttr
	private ConcurrentMap<SootClass, ClassAttr> classAttrs = new ConcurrentHashMap<SootClass, ClassAttr>();
	// maps class pair string to ClassPair
	private ConcurrentMap<String, ClassesPair> classesPairs = new ConcurrentHashMap<String, ClassesPair>();
	// maps method signature to List<AstNode>
	private ConcurrentMap<String, List<AstNode>> apiResults = new ConcurrentHashMap<String, List<AstNode>>();
	
	public Iterable<ClassesPair> getClassesPairs() {
		return classesPairs.values();
	}
	
	public Iterable<ClassAttr> getClassAttrs() {
		return classAttrs.values();
	}
	
	/**
	 * Set soot options based on current configurations.
	 */
	public void setSootOptions(SootConfigUtil sootConfig) {
		String intype = sootConfig.getIntype();
		if (intype.equals("APK")) {
			soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_apk);
			soot.options.Options.v().set_process_multiple_dex(true);
		} else if (intype.equals("DEX")) {
			soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_apk);
		} else if (intype.equals("SOURCE")) {
			// Java frontend is outdated
			// https://github.com/Sable/soot/issues/796
			System.err.println("Soot Java frontend is outdated and should be avoided! Compile them into class or jar first!");
			soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_java);
		} else if (intype.equals("CLASS")) {
			soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_only_class);
		} else if (intype.equals("JAR")) {
			soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_only_class);
		} else {
			System.err.println("Unknown input type: " + intype);
		}
		
		// WARNING: we need JIMPLE output to be able to process static final fields in <clinit> methods.		
		soot.options.Options.v().set_output_format(soot.options.Options.output_format_J);
		soot.options.Options.v().set_keep_line_number(true);
		soot.options.Options.v().set_allow_phantom_refs(true);
		// Java class input would require process_dir to consider package folders
		// https://github.com/Sable/soot/issues/796
		if (sootConfig.getProcessDir() != null && !sootConfig.getProcessDir().isEmpty())
			soot.options.Options.v().set_process_dir(Arrays.asList(sootConfig.getProcessDir()));
		// soot.options.Options.v().set_whole_program(true);
	}
		
	/**
	 * The function is the main function to extract signatures from jar/classes/apks.
	 * The global object *config* are used to perform analysis.
	 */
	public void analyze(String inpath, String outfile, String sigOutfile, String pkgName, String pkgVersion) {
		// 1. run packs, map SootMethod to method bodies
		// FIXME: threadCount for soot is specified internally and cannot be changed
		long t1 = System.currentTimeMillis();
		final ConcurrentHashMap<SootMethod, Body> bodies = new ConcurrentHashMap<SootMethod, Body>();
		
		PackManager.v().getPack("jtp").add(new Transform("jtp.classSignatures", new BodyTransformer() {
			@Override
			protected void internalTransform(Body b, String phaseName,
					Map<String, String> options) {
				
				bodies.put(b.getMethod(), b);
			}
		}));
		
		File inFile = new File(inpath);
		String outputBasename = inFile.getName();
		int suffixIndex = outputBasename.lastIndexOf(".");
		if (suffixIndex != -1) outputBasename = outputBasename.substring(0, suffixIndex);
		String sootOutDir = sootConfig.getSootOutDir();
		if (sootOutDir != null && !sootOutDir.isEmpty()) sootOutDir = sootOutDir + File.separator + outputBasename;
		else sootOutDir = "/tmp" + File.separator + outputBasename;

		String[] sootArgs = null;
		String androidJarDir = sootConfig.getAndroidJarDir(); 
		// configBuilder.setForceAndroidJarPath(configBuilder.getAndroidJarDirPath() + "/android-21/android.jar");
		if (androidJarDir!= null && !androidJarDir.isEmpty()) {
			// If the input type is DEX or APK, then android jar path must exist! 
			sootArgs = new String[]{
				"-android-jars",
				androidJarDir,
				"-d",
				sootOutDir,
				"-force-android-jar",
				androidJarDir + "/android-21/android.jar"
			};
		} else if (sootConfig.getIntype().equals("DEX") || sootConfig.getIntype().equals("APK")) {
			// Expect Android Jar, but doesn't have Android Jar Path
			System.err.println("Expect Android Jar for input type, but Android Jar is not provided!");
		} else {
			sootArgs = new String[]{
				"-d",
				sootOutDir,
			};
		}
		soot.Main.main(sootArgs);
		
		// 2. extract signatures
		long t2 = System.currentTimeMillis();
		extractSignatures(Scene.v().getClasses(), bodies);
		
		// 3. prepare ast result
		long t3 = System.currentTimeMillis();
		dumpPkgAstResults(inpath, outfile, pkgName, pkgVersion);
		
		// 4. optionally prepare class result
		long t4 = System.currentTimeMillis();
		if (!sigOutfile.isEmpty())
			dumpPkgClassMethodResult(inpath, sigOutfile, pkgName, pkgVersion);

		// 5. optionally show statistics
		long t5 = System.currentTimeMillis();
		if (sootConfig.isShowStats())
			System.out.println("Run packs took " + (t2 - t1) + "\n" +
							   "Extract signatures took " + (t3 - t2) + "\n" +
							   "Dump ast result to file took " + (t4 - t3) + "\n" +
							   "Dump class result to file took " + (t5 - t4) + "\n" + 
							   "Total elapsed time is: " + (t5 - t1) + " milliseconds.\n");
		
		// 6. remove intermediate soot output if instructed!
		if (!sootConfig.isKeepSootOutput())
			try {
				FileUtils.deleteDirectory(new File(sootOutDir));
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	}
	
	/**
	 * Extract the signatures of all the provided classes
	 * @param allClasses, all the classes
	 * @param bodies, all
	 */
	private void extractSignatures(Chain<SootClass> allClasses, Map<SootMethod, Body> bodies) {
		/* Invocation related, these are information that is actually invoked
		 */
		// initialize PSCout
		psCout = new PSCout(PermissionUtil.getDataDir() + File.separator + "jellybean_allmappings",
				PermissionUtil.getDataDir() + File.separator + "jellybean_intentpermissions");
		int threadNum = sootConfig.getThreadCount() > 0? sootConfig.getThreadCount(): Runtime.getRuntime().availableProcessors();
		
		CountingThreadPoolExecutor executor =  new CountingThreadPoolExecutor(threadNum,
				threadNum, 30, TimeUnit.SECONDS,
				new LinkedBlockingQueue<Runnable>());
		
		Iterator<SootClass> iterClass = allClasses.iterator();
		// Improve efficiency
		final Map<String, SootClass> className2Class = new HashMap<String, SootClass>();
		for ( SootClass sc : allClasses ) {
			className2Class.put(sc.getName(), sc);
		}
		while( iterClass.hasNext() ) {
			final SootClass c = iterClass.next();
		   	executor.execute(new Runnable() {
				
				@Override
				public void run() {
					extractSignatureWorker(className2Class, bodies, c);
				}
				
		   	});
		}
		
		// Wait till all packs have been executed
		try {
			executor.awaitCompletion();
			executor.shutdown();
		} catch (InterruptedException e) {
			// Something went horribly wrong
			throw new RuntimeException("Could not wait for extract threads to finish: " + e.getMessage(), e);
		}
		
		// If something went wrong, we tell the world
		if (executor.getException() != null)
			throw (RuntimeException) executor.getException(); 
	}
	
	private void extractSignatureWorker(Map<String, SootClass> className2Class, Map<SootMethod, Body> bodies, SootClass sootClass) {
		if (!sootClass.isApplicationClass()) return; 
		ClassAttr classAttr = classAttrs.computeIfAbsent(sootClass, sc -> new ClassAttr(sc));
		// 1. super class, innner classes
		if (sootClass.hasSuperclass()) {
			SootClass superClass = sootClass.getSuperclass();
			if (className2Class.containsKey(superClass.getName())) {
				ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), superClass.getName(), 
						superClass.isApplicationClass(), ClassRelation.INHERITANCE.getIndex());
			}
		}
		if (sootClass.hasOuterClass()) {
			SootClass outerClass = sootClass.getOuterClass();
			ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), outerClass.getName(), 
					outerClass.isApplicationClass(), ClassRelation.OUTER_CLASS.getIndex());			
			classAttr.setOuterClassName(outerClass.getName());
		} else if (sootClass.getName().contains("$")) {
			// TODO: This is a temporary fix to the outer class relationship
			try {
				// Get the outer class, and strip trailing extra $ characters!
				String possibleOuterClass = StringUtils.stripEnd(sootClass.getName().substring(0, sootClass.getName().lastIndexOf('$')), "$");
				SootClass outerClass = Scene.v().getSootClass(possibleOuterClass);
				if (outerClass != null) { 
					ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), outerClass.getName(), 
							outerClass.isApplicationClass(), ClassRelation.OUTER_CLASS.getIndex());
					classAttr.setOuterClassName(outerClass.getName());
				}
			} catch (Exception e) {
				// The soot class may not exist
				// e.printStackTrace();
			}
		}
		// 2. interface
		Chain<SootClass> interfaces = sootClass.getInterfaces();		
		if (interfaces != null) {
			for (SootClass impl : interfaces) {
				if (className2Class.containsKey(impl.getName())) {
					ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), impl.getName(), 
							impl.isApplicationClass(), ClassRelation.IMPL.getIndex());
				}
			}
		}
		// 3. static & instance fields
		//static & instance fields
		for (SootField field : sootClass.getFields()) {
			Type type = field.getType();
			if (type instanceof ArrayType) {
				//array field
				ArrayType arrayType = (ArrayType) type;
				SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, arrayType.baseType); 
				if (typeClass != null) {
					if (field.isStatic()) {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.STATIC_ARRAY_FIELD.getIndex());
					} else {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.INSTANCE_ARRAY_FIELD.getIndex());
					}
				}
			} else {
				//base type field
				SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, type);
				if (typeClass != null) {
					if (field.isStatic()) {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.STATIC__FIELD.getIndex());						
					} else {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.INSTANCE_FIELD.getIndex());
					}
				}
			}
		}
		
		// 4. methods, <init>, <clinit>, and other methods
		// 4.1 method prototype
		// 4.2 locals
		// 4.3 constant strings, each method, as well as in <init> and <clinit>
		// 4.4 basic block level information, including seq_num, loop_depth, in/out_degree and number of statements
		// 4.5 invoke framework APIs & permission related APIs & other classes methods & same class methods
		List<SootMethod> methods = sootClass.getMethods();
		for (SootMethod method : methods) {
			MethodAttributeProto.Builder methodProto = MethodAttributeProto.newBuilder();
			methodProto.setClassName(sootClass.getName());
			methodProto.setMethodName(method.getName());
			methodProto.setMethodSignature(method.getSignature());
			methodProto.setMethodSubsignature(method.getSubSignature());
			methodProto.setModifiers(Modifier.toString(method.getModifiers()));

			// 4.1 method prototype
			List<Type> parameterTypes = method.getParameterTypes();
			for (Type parameterType : parameterTypes) {
				methodProto.addParamterTypes(parameterType.toString());
				if (parameterType instanceof ArrayType) {
					ArrayType arrayType = (ArrayType) parameterType;
					SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, arrayType.baseType); 
					if (typeClass != null) {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.METHOD_ARRAY_PARAMERTER.getIndex());
					}
				} else {
					SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, parameterType);					
					if (typeClass != null) {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.METHOD_PARAMETER.getIndex());
					}
				}
			}
			Type returnType = method.getReturnType();
			methodProto.setReturnType(returnType.toString());
			if (returnType instanceof ArrayType) {
				ArrayType arrayType = (ArrayType) returnType;
				SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, arrayType.baseType);
				if (typeClass != null) {
					ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
							typeClass.isApplicationClass(), ClassRelation.METHOD_ARRAY_RETURN.getIndex());
				}
			} else {
				SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, returnType);					
				if (typeClass != null) {
					ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
							typeClass.isApplicationClass(), ClassRelation.METHOD_RETURN.getIndex());
				}
			}
			Body body = bodies.get(method);
			if (body == null) continue;				

			// 4.2 locals
			List<Local> locals = Lists.newArrayList(body.getLocals());
			for (Local local : locals) {
				Type type = local.getType();
				methodProto.addLocalTypes(type.toString());
				if (type instanceof ArrayType) {
					ArrayType arrayType = (ArrayType) type;
					SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, arrayType.baseType);
					if (typeClass != null) {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.METHOD_ARRAY_LOCAL.getIndex());
					}
				} else {
					SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, type);						
					if (ClassSignaturesUtil.isTypeExist(className2Class, type)) {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.METHOD_LOCAL.getIndex());
					}
				}
			}
			
			// 4.4 basic blocks, required for Centroid computation
			// reference: http://stackoverflow.com/questions/6792305/identify-loops-in-java-byte-code
			if (sootConfig.isKeepBBInfo()) {
				try {
					BasicBlockUtil bbu = new BasicBlockUtil(body);
					for (Block block: bbu.getBlocks()) {
						BasicBlockProto.Builder blockProto = BasicBlockProto.newBuilder();
						blockProto.setSequenceNumber(bbu.getBlockSequenceNumber(block));
						blockProto.setInDegree(bbu.getInDegree(block));
						blockProto.setOutDegree(bbu.getOutDegree(block));
						blockProto.setInDegreeUnexceptional(bbu.getInDegreeUnexceptional(block));
						blockProto.setOutDegreeUnexceptional(bbu.getOutDegreeUnexceptional(block));
						blockProto.setLoopDepth(bbu.getLoopLevel(block));
						blockProto.setStmtCount(bbu.getStmtCount(block));
						blockProto.addAllPredecessors(bbu.getPredecessors(block));
						blockProto.addAllSuccessors(bbu.getSuccessors(block));
						for (SootMethod blockInvokeMethod: bbu.getInvokeMethods(block)) {
							blockProto.addInvokedMethodSignatures(blockInvokeMethod.getSignature());
						}
						int dominatorSeqNum = bbu.getDominatorSequenceNumber(block);
						if (dominatorSeqNum != -1)  blockProto.setDominatorSequenceNumber(dominatorSeqNum);
						// blockProto.setBlockContent(block.toString());
						methodProto.addBlocks(blockProto.build());
					}
					// calculate Centroid and Centroid with Invoke
					BasicBlockUtil.computeAndSetCentroid(methodProto);
				} catch (Exception e) {
					System.out.println("Exception failed to compute basic block information for :" + body.getMethod());
					e.printStackTrace();
				} catch (Error e) {
					System.out.println("Error failed to compute basic block information for :" + body.getMethod() + ", Ignoring!");
					e.printStackTrace();
				}
			}
			
			// 4.3/4.5: iterate through each unit to find: constant strings, invoke expressions
			// Analyze whether the invoke expression is permission related or framework related
			PatchingChain<Unit> units = body.getUnits();
			for (Iterator<Unit> iter = units.iterator(); iter.hasNext();) {
				Unit unit = iter.next();
				if (unit instanceof AssignStmt) {
					AssignStmt assignStmt = (AssignStmt) unit;
					Value lV = assignStmt.getLeftOp();
					Value rV = assignStmt.getRightOp();
					
					ArrayList<Value> tmpVs = new ArrayList<Value>();
					tmpVs.add(lV);
					tmpVs.add(rV);
					for (Value tmpV : tmpVs) {
						if (tmpV instanceof Local) {
							Local local = (Local) tmpV;
							Type type = local.getType();
							if (type instanceof ArrayType) {
								ArrayType arrayType = (ArrayType) type;
								type = arrayType.baseType;
							}
							SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, type);
							if (typeClass != null) {
								ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
										typeClass.isApplicationClass(), ClassRelation.STMT_LOCAL_REF.getIndex());
							}
						} else if (tmpV instanceof ArrayRef) {
							ArrayRef arrayRef = (ArrayRef) tmpV;
							Type type = arrayRef.getBase().getType();
							if (type instanceof ArrayType) {
								ArrayType arrayType = (ArrayType) type;
								type = arrayType.baseType;
							}
							SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, type);
							if (typeClass != null) {
								ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
										typeClass.isApplicationClass(), ClassRelation.STMT_ARRAY_REF.getIndex());
							}
						} else if (tmpV instanceof StaticFieldRef) {
							StaticFieldRef staticFieldRef = (StaticFieldRef) tmpV;
							// If the referenced field is resource, we want to list them.
							SootField field = staticFieldRef.getField();
							if (field.toString().startsWith("R.")) {
								methodProto.addResourceRefs(field.toString());
							}
							SootClass varClass = field.getDeclaringClass();
							if (className2Class.containsKey(varClass.getName())) {
								ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), varClass.getName(), 
										varClass.isApplicationClass(), ClassRelation.STMT_STATIC_FIELD_REF.getIndex());
							}
						} else if (tmpV instanceof InstanceFieldRef) {
							InstanceFieldRef instanceFieldRef = (InstanceFieldRef) tmpV;
							SootClass varClass = instanceFieldRef.getField().getDeclaringClass();
							if (className2Class.containsKey(varClass.getName())) {
								ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), varClass.getName(), 
										varClass.isApplicationClass(), ClassRelation.STMT_INSTANCE_FIELD_REF.getIndex());
							}
						} else if (tmpV instanceof StringConstant) {
							/**
							 * AssignStmt, rightOp, can be a StringConstant
							 */
							StringConstant strConst = (StringConstant) tmpV;
							methodProto.addStringConstants(strConst.toString());
						} else if (tmpV instanceof Expr) {
							/**
							 * The interesting expressions are:
							 * CastExpr, InstanceOfExpr, NewExpr, NewMultiArray, NewArray, InvokeExpr
							 * 
							 * InvokeExpr, arg can be a StringConstant
							 */
							if (tmpV instanceof CastExpr) {
								CastExpr castExpr = (CastExpr) tmpV;
								Type type = castExpr.getCastType();
								Type immType = castExpr.getOp().getType();
								if (type instanceof ArrayType) {
									ArrayType arrayType = (ArrayType) type;
									type = arrayType.baseType;
								}
								if (immType instanceof ArrayType) {
									ArrayType arrayType = (ArrayType) immType;
									immType = arrayType.baseType;
								}
								SootClass toClass = ClassSignaturesUtil.getTypeClass(className2Class, immType);
								SootClass fromClass = ClassSignaturesUtil.getTypeClass(className2Class, type);
								if (toClass != null && fromClass != null) {
									ClassSignaturesUtil.updateClassesPair(classesPairs, toClass.getName(),
											fromClass.getName(), fromClass.isApplicationClass(), ClassRelation.CAST_EXPR.getIndex());
								}
							} else if (tmpV instanceof InstanceOfExpr) {
								InstanceOfExpr instanceOfExpr = (InstanceOfExpr) tmpV;
								Type type = instanceOfExpr.getCheckType();
								Type immType = instanceOfExpr.getOp().getType();
								if (type instanceof ArrayType) {
									ArrayType arrayType = (ArrayType) type;
									type = arrayType.baseType;
								}
								if (immType instanceof ArrayType) {
									ArrayType arrayType = (ArrayType) immType;
									immType = arrayType.baseType;
								}
								SootClass toClass = ClassSignaturesUtil.getTypeClass(className2Class, immType);
								SootClass fromClass = ClassSignaturesUtil.getTypeClass(className2Class, type);
								if (toClass != null && fromClass != null) {
									ClassSignaturesUtil.updateClassesPair(classesPairs, toClass.getName(),
											fromClass.getName(), fromClass.isApplicationClass(), ClassRelation.INSTANCE_OF_EXPR.getIndex());
								}
							} else if (tmpV instanceof NewExpr) {
								NewExpr newExpr = (NewExpr) tmpV;
								Type type = newExpr.getType();
								if (type instanceof ArrayType) {
									ArrayType arrayType = (ArrayType) type;
									type = arrayType.baseType;
								}
								SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, type);
								if (typeClass != null) {
									ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(),
											typeClass.getName(), typeClass.isApplicationClass(), ClassRelation.NEW_EXPR.getIndex());
								}
							} else if (tmpV instanceof NewMultiArrayExpr) {
								NewMultiArrayExpr newMultiArrayExpr = (NewMultiArrayExpr) tmpV;
								SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, newMultiArrayExpr.getBaseType().baseType);
								if (typeClass != null) {
									ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(),
											typeClass.getName(), typeClass.isApplicationClass(), ClassRelation.NEW_MULTI_ARRAY_EXPR.getIndex());
								}
							} else if (tmpV instanceof NewArrayExpr) {
								NewArrayExpr newArrayExpr = (NewArrayExpr) tmpV;
								SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, newArrayExpr.getBaseType());
								if (typeClass != null) {
									ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(),
											typeClass.getName(), typeClass.isApplicationClass(), ClassRelation.NEW_ARRAY_EXPR.getIndex());
								}
							} else if (tmpV instanceof InvokeExpr) {
								handleInvokeExpr((Expr) tmpV, sootClass, classAttr, methodProto, className2Class);
							} 
						}
					}
				} else if (unit instanceof InvokeStmt) {
					/**
					 * InvokeStmt, arg can be a StringConstant
					 */
					InvokeStmt invokeStmt = (InvokeStmt) unit;
					InvokeExpr invokeExpr = invokeStmt.getInvokeExpr();
					handleInvokeExpr((Expr) invokeExpr, sootClass, classAttr, methodProto, className2Class);
				} else if (unit instanceof ReturnStmt) {
					/**
					 * ReturnStmt, returnOp can be a StringConstant
					 */
					ReturnStmt returnStmt = (ReturnStmt) unit;
					if (returnStmt.getOp() instanceof StringConstant)
						methodProto.addStringConstants(returnStmt.getOp().toString());
					Type type = returnStmt.getOp().getType();
					if (type instanceof ArrayType) {
						ArrayType arrayType = (ArrayType) type;
						type = arrayType.baseType;
					}
					SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, type);
					if (typeClass != null) {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(),
								typeClass.getName(), typeClass.isApplicationClass(), ClassRelation.STMT_LOCAL_REF.getIndex());
					}
				} else {
					System.out.println("Unknown unit type: " + unit.getClass().getName());
				}
		
			}
			// Update the methodProto
			classAttr.addMethodProto(methodProto.build());
		}  // end method iteration
	}
	
	private boolean isLookupApi(String base, String name) {
		if (config.getApisCount() == 0)
			return true;
		for (AstNode node: config.getApisList()) {
			if (node.getBaseType().equals(base) && node.getName().equals(name))
				return true;
		}
		return false;
	}
	
	private boolean isLookupApi(String sig) {
		// FIXME: signature contains return type and arg type, and requires lookup config to specify them as well.
		return false;
	}
	
	private void handleInvokeExpr(Expr expr, SootClass sootClass, ClassAttr classAttr,
			MethodAttributeProto.Builder methodProto, Map<String, SootClass> allClasses) {
		InvokeExpr invokeExpr = (InvokeExpr) expr;
		
		SootMethod targetMethod = null;
		try {
			targetMethod = invokeExpr.getMethod();
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (targetMethod == null) {
			return;
		}
		SootClass targetClass = targetMethod.getDeclaringClass();
		if (allClasses.containsKey(targetClass.getName())) {
			// NOTE: Invoked signature may be recorded in BasicBlock, check if it is necessary to log here!
			if (!sootConfig.isKeepBBInfo())
				methodProto.addInvokedMethodSignatures(targetMethod.getSignature());
			
			// Update invoke information and permission information for ClassAttr
			if (!targetClass.isApplicationClass()) {
				classAttr.addSysCallStr(targetMethod.getSignature());
			}
			String targetMethodName = targetClass.getName()+ "." + targetMethod.getName();		
			String permission = psCout.getApiPermission(targetMethodName);
			if (permission != null) {
				classAttr.addPermissionStr(permission);
			}
			// Update invoke relationship and permission for ClassPair
			ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(),
					targetClass.getName(), targetClass.isApplicationClass(), ClassRelation.INVOKE_EXPR.getIndex(),
					permission);
		}
		
		List<Value> mArgs = invokeExpr.getArgs();
		for (Value arg : mArgs) {
			if (arg instanceof StringConstant)
				methodProto.addStringConstants(arg.toString());
			Type type = arg.getType();
			if (type instanceof ArrayType) {
				ArrayType arrayType = (ArrayType) type;
				type = arrayType.baseType;
			}
			SootClass typeClass = ClassSignaturesUtil.getTypeClass(allClasses, type);
			if (typeClass != null) {
				ClassesPair pair = ClassSignaturesUtil.getClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), typeClass.isApplicationClass());
				pair.relationNums[ClassRelation.STMT_LOCAL_REF.getIndex()] += 1;
			}
		}
		
		// TODO: use targetMethod.getSignature() to improve matching accuracy 
		String targetMethodBase = targetMethod.getDeclaringClass().getName();
		String targetMethodName = targetMethod.getName();
		String targetMethodFullName = targetMethodBase + "." + targetMethodName;
		if (isLookupApi(targetMethodBase, targetMethodName)) {
			// Update invoke information for ast lookup
			apiResults.putIfAbsent(targetMethodFullName, new ArrayList<AstNode>());
			List<AstNode> nodes = apiResults.get(targetMethodFullName);
			AstNode.Builder newNode = AstNode.newBuilder();
			// Set related fields for newNode
			newNode.setType(AstNode.NodeType.FUNCTION_DECL_REF_EXPR);
			newNode.setName(targetMethodName);
			newNode.setFullName(targetMethodFullName);
			newNode.setBaseType(targetMethodBase);
			for (Value arg: mArgs) {
				newNode.addArguments(arg.toString());
			}
			newNode.setSource(invokeExpr.toString());
			// Range is simplified to the enclosing class/method
			FileInfo.Builder fi = FileInfo.newBuilder();
			fi.setFilename(sootClass.getShortName());
			fi.setRelpath(sootClass.getPackageName());
			fi.setFile(sootClass.getName());
			SourceLocation.Builder sl = SourceLocation.newBuilder();
			sl.setFileInfo(fi);
			SourceRange.Builder sr = SourceRange.newBuilder();
			sr.setStart(sl);
			newNode.setRange(sr);
			nodes.add(newNode.build());
		}
	}
	
	private List<AstNode> getAllApiResults() {
		List<AstNode> allApiResults = new ArrayList<AstNode>();
		for (List<AstNode> nodes: apiResults.values()) {
			allApiResults.addAll(nodes);
		}
		return allApiResults;
	}
	
	private PkgAstResults dumpPkgAstResults(String inpath, String outfile, String pkgName, String pkgVersion) {
		PkgAstResults.Builder astResults = PkgAstResults.newBuilder();
		PkgAstResult.Builder astResult = PkgAstResult.newBuilder();
		
		// Prepare metadata
		astResult.setConfig(config);
		File inf = new File(inpath);
		if (pkgName != null && !pkgName.isEmpty()) astResult.setPkgName(pkgName);
		else astResult.setPkgName(inf.getName());
		if (pkgVersion != null && !pkgVersion.isEmpty()) astResult.setPkgVersion(pkgVersion);
		astResult.setLanguage(Language.JAVA);
		astResult.setInputPath(inpath);
		
		// Prepare analysis results
		if (config.getApisCount() > 0) {
			List<AstNode> allApiResults = getAllApiResults();
			astResult.addAllApiResults(allApiResults);
		}
		if (config.getSaveFeature()) {
			// TODO: set the rootNodes in ast result
		}
		
		astResults.addPkgs(astResult.build());

		// Save resultpb to file
		File outf = new File(outfile);
		try {
			ProtoBufferUtil.saveMessage(astResults.build(), outf, false);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
		return astResults.build();
	}

	private PkgClassMethodResult dumpPkgClassMethodResult(String inpath, String outfile, String pkgName, String pkgVersion) {
		PkgClassMethodResult.Builder classResult = PkgClassMethodResult.newBuilder();

		// Prepare metadata
		File inf = new File(inpath);
		if (pkgName != null && !pkgName.isEmpty()) classResult.setPkgName(pkgName);
		else classResult.setPkgName(inf.getName());
		if (pkgVersion != null && !pkgVersion.isEmpty()) classResult.setPkgVersion(pkgVersion);
		classResult.setLanguage(Language.JAVA);
		classResult.setInputPath(inpath);

		// Prepare analysis results
		for (ClassAttr classAttr : classAttrs.values()) {
			classResult.addClasses(classAttr.toProto());
		}
		for (ClassesPair pair : classesPairs.values()) {
			classResult.addClassPairs(pair.toProto());
		}

		// save resultpb to file
		File outf = new File(outfile);
		try {
			ProtoBufferUtil.saveMessage(classResult.build(), outf, false);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return classResult.build();
	}
}
