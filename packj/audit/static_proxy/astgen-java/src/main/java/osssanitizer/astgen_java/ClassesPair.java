package osssanitizer.astgen_java;

import java.util.HashSet;
import java.util.Set;

import proto.ClassSig.ClassRelationProto;
import proto.ClassSig.ClassRelationProto.RelationCounter;

public class ClassesPair {
	public String classname1 = null;
	public String classname2 = null;
	public boolean classname2IsApplicationClass;
	public Set<String> classname2Permissions = null;
	
	public int[] relationNums = new int[ClassRelation.ClassRelationNone.getIndex()];
	
	public ClassesPair(String firstClass, String secondClass) {
		this(firstClass, secondClass, false);
	}
	
	public ClassesPair(String firstClass, String secondClass, boolean secondClassIsApplicationClass) {
		this.classname1 = firstClass;
		this.classname2 = secondClass;
		this.classname2IsApplicationClass = secondClassIsApplicationClass;
		this.classname2Permissions = new HashSet<String>();		
	}
	
	@Override
	public boolean equals(Object object) {
		if (!(object instanceof ClassesPair)) {
			return false;
		}
		
		ClassesPair pair = (ClassesPair) object;
		return (this.classname1.equals(pair.classname1) && this.classname2.equals(pair.classname2));
	}
	
	@Override
	public int hashCode() {
		// Both hashCode and equals should be Override to be used in Set.contains(Object)
		return classname1.length() + classname2.length();
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(classname1);
		sb.append("#");
		sb.append(classname2);
		sb.append("#");
		for (int i = 0; i < relationNums.length; i++) {
			sb.append(relationNums[i]);
			sb.append('#');
		}
		return sb.toString();
	}
	
	public void setClassname2IsApplicationClass(boolean isApplicationClass) {
		this.classname2IsApplicationClass = isApplicationClass;
	}
	
	public boolean getClassname2IsApplicationClass() {
		return this.classname2IsApplicationClass;
	}
	
	public void addPermission(String permission) {
		this.classname2Permissions.add(permission);
	}
	
	public Set<String> getPermissions() {
		return this.classname2Permissions;
	}
	
	public ClassRelationProto toProto() {
		ClassRelationProto.Builder cr = ClassRelationProto.newBuilder();
		cr.setClassname1(this.classname1);
		cr.setClassname2(this.classname2);
		cr.setClassname2IsApplicationClass(this.classname2IsApplicationClass);
		cr.addAllClassname2Permissions(this.classname2Permissions);
		for (int relationIndex=0; relationIndex < this.relationNums.length; relationIndex++) {
			int relationNum = this.relationNums[relationIndex];
			if (relationNum > 0) {
				RelationCounter.Builder relCounter = RelationCounter.newBuilder();
				relCounter.setRelationType(ClassRelationProto.RelationType.valueOf(relationIndex));
				relCounter.setRelationCount(relationNum);
				cr.addRelationCounters(relCounter);
			}
		}
		return cr.build();
	}
}
