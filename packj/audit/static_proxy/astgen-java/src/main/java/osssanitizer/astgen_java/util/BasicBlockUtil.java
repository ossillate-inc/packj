package osssanitizer.astgen_java.util;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import proto.ClassSig.BasicBlockProto;
import proto.ClassSig.Centroid;
import proto.ClassSig.MethodAttributeProto;
import soot.Body;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.toolkits.annotation.logic.Loop;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.ExceptionalBlockGraph;
import soot.toolkits.graph.LoopNestTree;
import soot.toolkits.graph.MHGPostDominatorsFinder;

/**
 * Process the body of a method, and construct BlockGraph of it. 
 * 
 * @author ruian
 *
 */
public class BasicBlockUtil {
	// Loop related
	private LoopNestTree loopNestTree;
	private HashMap<Block, Integer> block2LoopLevel;
	// Basic block related
	private ExceptionalBlockGraph blockGraph;
	private MHGPostDominatorsFinder<Block> postDominators;
	private HashMap<Block, Integer> block2SequenceNumber;
	private Set<Block> visitedBlocks;
	private Body body;
	
	public BasicBlockUtil (Body body) {
		// variable initialization
		this.body = body;
		block2LoopLevel = new HashMap<Block, Integer>();
		block2SequenceNumber = new HashMap<Block, Integer>();
		loopNestTree = null;
		postDominators = null;
		
		// First create the block graph
		blockGraph = new ExceptionalBlockGraph(body);
		System.out.println("block graph for " + body.getMethod() + " has blocks " + blockGraph.getBlocks().size());

		if (blockGraph.size() == 1) {
			Block singleBlock = blockGraph.getBlocks().get(0);
			block2LoopLevel.put(singleBlock, 0);
			block2SequenceNumber.put(singleBlock, 1);
		} else if (blockGraph.size() == 0) {
			System.out.println("Warning: method " + body.getMethod() + " has no basic block!");
		} else {
			loopNestTree = new LoopNestTree(body);
			System.out.println("loop nest tree" + body.getMethod() + " has loops " + loopNestTree.size());
			// Dominators
			// reference: https://ssebuild.cased.de/nightly/soot/javadoc/soot/toolkits/graph/MHGPostDominatorsFinder.html
			// reference: https://en.wikipedia.org/wiki/Dominator_(graph_theory)
			postDominators = new MHGPostDominatorsFinder<Block>(blockGraph);
			try {
				mapBlock2LoopLevel();
				traverseBlockGraph();
			} catch (Exception e) {
				System.out.println("Error processing method body for: " + body.getMethod());
				e.printStackTrace();
			} catch (Error e) {
				System.out.println("Error processing method body for: " + body.getMethod());
				throw e;
			}
		}
	}
	
	/**
	 * Maps blocks to loop level.
	 */
	private void mapBlock2LoopLevel() {
		Map<Loop, Integer> loop2Level = new HashMap<Loop, Integer>();
		for (Loop loop: loopNestTree) {
			int higherCount = 0;
			Loop higherLoop = loop;
			while (loopNestTree.higher(higherLoop) != null) {
				higherCount += 1;
				higherLoop = loopNestTree.higher(higherLoop);
			}
			loop2Level.put(loop, higherCount + 1);
		}
		for (Block block : blockGraph) {
			Unit firstUnit = block.getHead();
			int deepestLoop = 0;
			for (Loop loop: loop2Level.keySet()) {
				// Match the firstUnit against each loop
				if (loop.getLoopStatements().contains(firstUnit) && loop2Level.get(loop) > deepestLoop) {
					deepestLoop = loop2Level.get(loop);
				 }
			}
			block2LoopLevel.put(block, deepestLoop);
		}
	}
	
	// The comparator class
	static class BlockComparator implements Comparator<Block> {
		 @Override
	    public int compare(Block o1, Block o2) {
	    	// First, compare number of successor blocks
	    	int o1SuccsCount = o1.getSuccs().size();
	    	int o2SccusCount = o2.getSuccs().size();
	    	if (o1SuccsCount != o2SccusCount) {
	    		return o1SuccsCount < o2SccusCount? -1 : 1;
	    	}
	    	// Second, compare number of predecessor blocks
	    	int o1PredsCount = o1.getPreds().size();
	    	int o2PredsCount = o2.getPreds().size();
	    	if (o1PredsCount != o2PredsCount) {
	    		return o1PredsCount < o2PredsCount? -1 : 1;
	    	}
	    	// Third, compare number of statements
	    	List<Unit> o1Units = new ArrayList<Unit>();
	    	for (Unit u: o1) o1Units.add(u);
	    	List<Unit> o2Units = new ArrayList<Unit>();
	    	for (Unit u: o2) o2Units.add(u);
	    	int o1StmtCount = o1Units.size();
	    	int o2StmtCount = o2Units.size();
	    	if (o1StmtCount != o2StmtCount) {
	    		return o1StmtCount < o2StmtCount? -1: 1;
	    	}
	    	// Fourth, compare the binary value of the each statement
	    	int returnValue = 0;
	    	for (int i=0; i<o1Units.size(); i++) {
	    		BigInteger o1BinaryValue = getInt(o1Units.get(i).toString());
	    		BigInteger o2BinaryValue = getInt(o2Units.get(i).toString());
	    		returnValue = o1BinaryValue.compareTo(o2BinaryValue);
	    		if (returnValue != 0) {
	    			return returnValue;
	    		}
	    	}
	    	// Fifth, if all the binary values are the same, then compare the successors' id and predecessors' id (soot assigned ids).
	    	// if even these ids are the same, then we cannot differentiate between the two blocks and therefore they are equal.
	    	if (returnValue == 0) {
	    		System.out.println("cannot compare block " + o1 + " and block " + o2 + " deterministicly!" +
	    				"inspecting their predecessors and successors default ids (assigned by soot)!");

	    		// Compare their successors! Find different ones, sort them, and compare one by one!
    			List<Integer> o1Succs = new ArrayList<Integer>();
    			for (Block o1s: o1.getSuccs()) {
    				if (!o2.getSuccs().contains(o1s)) o1Succs.add(o1s.getIndexInMethod());
    			}
    			if (o1Succs.size() > 0) {
        			List<Integer> o2Succs = new ArrayList<Integer>();    				
        			for (Block o2s: o2.getSuccs()) {
        				if (!o1.getSuccs().contains(o2s)) o2Succs.add(o2s.getIndexInMethod());
        			}
        			Collections.sort(o1Succs);
        			Collections.sort(o2Succs);
        			for (int j=0; j<o1Succs.size(); j++) {
        				returnValue = o1Succs.get(j) - o2Succs.get(j);
        				if (returnValue != 0) {
        					returnValue = returnValue < 0? -1: 1;
        					System.out.println("comparing successors successful! block " + o1.getIndexInMethod() +
        							"'s succ block " + o1Succs.get(j) + " is different " + returnValue + 
        							" from block " + o2.getIndexInMethod() + "'s succ block " + o2Succs.get(j));
        					return returnValue;
        				}
        			}
	    		}
    			
    			// Compare their predecessors! Find different ones, sort them, and compare one by one!
    			List<Integer> o1Preds = new ArrayList<Integer>();
    			for (Block o1p: o1.getPreds()) {
    				if (!o2.getPreds().contains(o1p)) o1Preds.add(o1p.getIndexInMethod());
    			}
    			if (o1Preds.size() > 0) {
        			List<Integer> o2Preds = new ArrayList<Integer>();
        			for (Block o2p: o2.getPreds()) {
        				if (!o1.getPreds().contains(o2p)) o2Preds.add(o2p.getIndexInMethod());
        			}
        			Collections.sort(o1Preds);
        			Collections.sort(o2Preds);
        			for (int j=0; j<o1Preds.size(); j++) {
        				returnValue = o1Preds.get(j) - o2Preds.get(j);
        				if (returnValue != 0) {
        					returnValue = returnValue < 0? -1: 1;
        					System.out.println("comparing predecessors successful! block " + o1.getIndexInMethod() +
        							"'s pred block " + o1Preds.get(j) + " is different " + returnValue +
        							" from block " + o2.getIndexInMethod() + "'s pred block " + o2Preds.get(j));
        					return returnValue;
        				}
        			}
	    		}
    			
    			// If successors and predecessors are the same, then they are equal
    			if (o1Succs.size() == 0 && o1Preds.size() == 0) {
	    			System.out.println("They have same predecessors and successors, they should be equal!");
	    			return 0;
    			} else {
    				// Error! This shouldn't happen, because we are comparing based on default ids assigned by Soot!
    	    		System.out.println("Cannot compare block " + o1 + " and block " + o2 + " deterministicly even based on predecessors and successors!");
    	    		return 0;
    			}
	    	}
	    	// Shouldn't reach here!
			return returnValue;
	    }
	    
	    BigInteger getInt(String plaintext) {
	    	MessageDigest m;
	    	BigInteger bigInt = new BigInteger("0");
			try {
				m = MessageDigest.getInstance("MD5");
		    	m.reset();
		    	m.update(plaintext.getBytes());
		    	byte[] digest = m.digest();
		    	bigInt = new BigInteger(1, digest);					
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    	return bigInt;
	    }
	}
	
	// The key point is that the traversal should be deterministic!
	private int visitNode(Block node, Set<Block> stop, int sequenceNumber) {
		if ((stop != null && stop.contains(node)) || visitedBlocks.contains(node)) {
			// Current node shouldn't be visited! Which means next node should still reuse this sequenceNumber
			// i.e. this sequenceNumber is not consumed!
			return sequenceNumber;
		}
		// System.out.println("Visiting block " + sequenceNumber + " of method " + node.getBody().getMethod() + ", content:" + node);
		visitedBlocks.add(node);
		block2SequenceNumber.put(node, sequenceNumber);
		
		// get all children, and make the list modifiable, so that we can sort them! get rid of visited blocks
		List<Block> succs = new ArrayList<Block>();
		for (Block succ: node.getSuccs()) {
			// Skip visited blocks
			if ((stop != null && stop.contains(succ)) || visitedBlocks.contains(succ)) { 
				// ignore stop nodes, or visited blocks 
			}
			else succs.add(succ);
		}
		
		int nextId = sequenceNumber + 1;		
		if (succs.size() == 0) {
			// this is exit, and has no successors! simply return the next node's sequenceNumber
			return nextId;
		} else if (succs.size() == 1) {
			// this is not branch node, or the branch node doesn't have more than one unvisited successors!
			return visitNode(succs.get(0), stop, nextId);
		} else {
			Block dominator = null;
			try {
				// the exit blocks may not have post dominator
				dominator = postDominators.getImmediateDominator(node);
			} catch (Exception e) {
				System.out.println("Error trying to get dominator of node: " + node);
				e.printStackTrace();
			} catch (Error e) {
				System.out.println("Error trying to get dominator of node: " + node);
				throw e;
			}
			
			// sort the successors
			// reference: http://stackoverflow.com/questions/2784514/sort-arraylist-of-custom-objects-by-property			
			// System.out.println("block " + node.getIndexInMethod() + " has " + succs.size() + " successors! Sorting them now!");
			Collections.sort(succs, new BlockComparator());
			// visit successors one-by-one, in descending order
			Collections.reverse(succs);
			
			try {	
				// Visit all the succesors, but they will abort at dominator
				Set<Block> newStop = null;
				if (dominator != null) {
					// reuse the old stop
					newStop = new HashSet<Block>();
					if (stop != null) newStop.addAll(stop);
					newStop.add(dominator);
				} else newStop = stop;
				for (Block succ: succs) {
					nextId = visitNode(succ, newStop, nextId);
				}
				
				// Continue visiting dominator
				if (dominator == null) return nextId;
				else return visitNode(dominator, stop, nextId);
				
			} catch (Exception e) {
				System.out.println("Error when sequenceNumber is " + sequenceNumber + " and nextId is " + nextId +
						",\n visiting block: " + node + "\n and has dominator: " + dominator);
				System.out.println("Successors are: " + succs);
				e.printStackTrace();
			} catch (Error e) {
				System.out.println("Error when sequenceNumber is " + sequenceNumber + " and nextId is " + nextId +
						",\n visiting block: " + node + "\n and has dominator: " + dominator);
				System.out.println("Successors are: " + succs);
				throw e;
			}
		}
		System.out.println("Error visiting node, shouldn't reach here, node is: " + node);
		return nextId;
	}
	
	private void traverseBlockGraph() throws Exception {
		List<Block> heads = blockGraph.getHeads();
		visitedBlocks = new HashSet<Block>();
		
		// There can be multiple heads, because each trap handler is a head! However, we ignore them! Because they will
		// be successors of other blocks!
		Block startBlock = null;
		if (heads.size() == 1) {
			startBlock = heads.get(0);
		} else if (heads.size() > 1) {
			// pick one block that has no predecessors
			for (Block b: heads) {
				if (b.getPreds().size() == 0) {
					startBlock = b;
					break;
				}
			}
			if (startBlock == null) {
				startBlock = heads.get(0);
				System.out.println("Warning! In " + body.getMethod() + 
						" all heads have non-zero pred count, head count:" + blockGraph.getHeads().size());				
			}
		} else {
			throw new Exception("The number of heads is 0, should never happen!");
		}

		int largestSequenceNumber = visitNode(startBlock, null, 1) - 1;
		if (largestSequenceNumber != blockGraph.size()) {
			// TODO: try visit the other heads to assign sequence numbers, for the remaining blocks.
			// if it still doesn't work, use the default sequence numbers assigned by soot?
			System.out.println("Warning! largestSequenceNumber is " + largestSequenceNumber +
					", but the total number of blocks is " + blockGraph.size() +
					", the blocks graph is " + blockGraph);
		}
	}
	
	public List<Block> getBlocks() {
		return blockGraph.getBlocks();
	}
	
	public int getBlockSequenceNumber(Block block) {
		return block2SequenceNumber.get(block);
	}
	
	public int getInDegree(Block block) {
		return blockGraph.getPredsOf(block).size();
	}
	
	public int getOutDegree(Block block) {
		return blockGraph.getSuccsOf(block).size();
	}
	
	public int getInDegreeUnexceptional(Block block) {
		return blockGraph.getUnexceptionalPredsOf(block).size();
	}
	
	public int getOutDegreeUnexceptional(Block block) {
		return blockGraph.getUnexceptionalSuccsOf(block).size();
	}
	
	public int getLoopLevel(Block block) {
		return block2LoopLevel.get(block);
	}
	
	public List<Integer> getPredecessors(Block block) {
		List<Integer> predecessors = new ArrayList<Integer>();
		for (Block pred: block.getPreds()) {
			predecessors.add(getBlockSequenceNumber(pred));
		}
		return predecessors;
	}
	
	public List<Integer> getSuccessors(Block block) {
		List<Integer> successors = new ArrayList<Integer>();
		for (Block succ: block.getSuccs()) {
			successors.add(getBlockSequenceNumber(succ));
		}
		return successors;
	}
	
	public int getDominatorSequenceNumber(Block block) {
		if (postDominators == null) {
			return -1;
		}
		Block dominator = postDominators.getImmediateDominator(block);
		if (dominator == null) {
			return -1;
		} else {
			return getBlockSequenceNumber(dominator);
		}
	}
	
	public static int getStmtCount(Block block) {
		int stmtCount = 0;
		for (Unit unit: block) stmtCount += 1;
		return stmtCount;
	}
	
	public static List<SootMethod> getInvokeMethods(Block block) {
		List<SootMethod> invokedMethods = new ArrayList<SootMethod>();
		for (Unit unit : block) {
			if (unit instanceof AssignStmt) {
				AssignStmt assignStmt = (AssignStmt) unit;
				Value lV = assignStmt.getLeftOp();
				Value rV = assignStmt.getRightOp();

				ArrayList<Value> tmpVs = new ArrayList<Value>();
				tmpVs.add(lV);
				tmpVs.add(rV);
				for (Value tmpV : tmpVs) {
					if (tmpV instanceof InvokeExpr) {
						InvokeExpr invokeExpr = (InvokeExpr) tmpV;
						SootMethod targetMethod = null;
						try {
							targetMethod = invokeExpr.getMethod();
						} catch (Exception e) {
							e.printStackTrace();
						}
						if (targetMethod == null) {
							continue;
						}
						invokedMethods.add(targetMethod);	
					}
				}
			} else if (unit instanceof InvokeStmt) {
				InvokeStmt invokeStmt = (InvokeStmt) unit;
				InvokeExpr invokeExpr = invokeStmt.getInvokeExpr();
				SootMethod targetMethod = null;
				try {
					targetMethod = invokeExpr.getMethod();
				} catch (Exception e) {
					e.printStackTrace();
				}
				if (targetMethod == null) {
					continue;
				}
				invokedMethods.add(targetMethod);
			}
		}
		
		return invokedMethods;
	}
	
	public static void computeAndSetCentroid(MethodAttributeProto.Builder methodProto) {
		// The basic block must have been set! And this function is used to set centroids!
		Centroid.Builder centroid = Centroid.newBuilder();
		Centroid.Builder centroidWithInvoke = Centroid.newBuilder();
		if (methodProto.getBlocksCount() > 1) {
			Map<Integer, BasicBlockProto> seqNum2Block = new HashMap<Integer, BasicBlockProto>();
			for (BasicBlockProto bbp: methodProto.getBlocksList()) {
				seqNum2Block.put(bbp.getSequenceNumber(), bbp);
			}
			for (BasicBlockProto bbp: methodProto.getBlocksList()) {
				int bbpW = bbp.getStmtCount();
				int bbpWInvoke = bbpW + bbp.getInvokedMethodSignaturesCount();
				for (int succId: bbp.getSuccessorsList()) {
					BasicBlockProto succ = seqNum2Block.get(succId);
					int succW = succ.getStmtCount();
					int succWInvoke = succW + succ.getInvokedMethodSignaturesCount();
					// compare bbp with succ
					centroid.setX(centroid.getX() + bbpW * bbp.getSequenceNumber() +  succW * succ.getSequenceNumber());
					centroid.setY(centroid.getY() + bbpW * bbp.getOutDegree() + succW * succ.getOutDegree());
					centroid.setZ(centroid.getZ() + bbpW * bbp.getLoopDepth() + succW * succ.getLoopDepth());
					centroid.setW(centroid.getW() + bbpW + succW);
					// centroidWithInvoke
					centroidWithInvoke.setX(centroidWithInvoke.getX() + bbpWInvoke * bbp.getSequenceNumber() +  succWInvoke * succ.getSequenceNumber());
					centroidWithInvoke.setY(centroidWithInvoke.getY() + bbpWInvoke * bbp.getOutDegree() + succWInvoke * succ.getOutDegree());
					centroidWithInvoke.setZ(centroidWithInvoke.getZ() + bbpWInvoke * bbp.getLoopDepth() + succWInvoke * succ.getLoopDepth());
					centroidWithInvoke.setW(centroidWithInvoke.getW() + bbpWInvoke + succWInvoke);				
				}
			}
			centroid.setX(centroid.getX() / centroid.getW());
			centroid.setY(centroid.getY() / centroid.getW());
			centroid.setZ(centroid.getZ() / centroid.getW());
			centroidWithInvoke.setX(centroidWithInvoke.getX() / centroidWithInvoke.getW());
			centroidWithInvoke.setY(centroidWithInvoke.getY() / centroidWithInvoke.getW());
			centroidWithInvoke.setZ(centroidWithInvoke.getZ() / centroidWithInvoke.getW());
		} else if (methodProto.getBlocksCount() == 1){
			BasicBlockProto bbp = methodProto.getBlocks(0);
			centroid.setX(bbp.getSequenceNumber());
			centroid.setY(bbp.getOutDegree());
			centroid.setZ(bbp.getLoopDepth());
			centroid.setW(bbp.getStmtCount());
			centroidWithInvoke.setX(bbp.getSequenceNumber());
			centroidWithInvoke.setY(bbp.getOutDegree());
			centroidWithInvoke.setZ(bbp.getLoopDepth());
			centroidWithInvoke.setW(bbp.getStmtCount() + bbp.getInvokedMethodSignaturesCount());
		} else {
			// no blocks
			centroid.setX(0);
			centroid.setY(0);
			centroid.setZ(0);
			centroid.setW(0);
			centroidWithInvoke.setX(0);
			centroidWithInvoke.setY(0);
			centroidWithInvoke.setZ(0);
			centroidWithInvoke.setW(0);
		}
			
		methodProto.setCentroid(centroid.build());
		methodProto.setCentroidWithInvoke(centroidWithInvoke.build());
	}
}
