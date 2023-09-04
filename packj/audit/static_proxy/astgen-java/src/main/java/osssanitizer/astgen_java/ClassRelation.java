package osssanitizer.astgen_java;


/**
 *	
 * For a class, it has:
 * 	-- parent class
 * 	-- implemented interfaces (ignore)
 *  -- outer class
 * 
 *  -- static fields
 *  -- instance fields
 *  -- methods
 *  
 * For a method, it has:
 *	-- prototype: parameters, return type
 *  -- local variables
 *  -- statements
 *  
 * Statements we care about:
 * 	-- AssignStmt: left value, right value
 *	-- InvokeStmt: InvokeExpr
 * 
 * Left Value:
 *  -- array_ref, instance_field_ref, static_field_ref, local
 *  
 * Right Value:
 *  -- array_ref, constant, instance_field_ref, static_field_ref, local, expr
 *  
 * Expr:
 *  -- cast_expr, instance_of_expr, invoke_expr, new_array_expr, new_expr, new_multi_array_expr
 *  
 * InvokeExpr:
 *  -- interface_invoke_expr, special_invoke_expr, static_invoke_expr, virtual_invoke_expr
 * 
 * Different relations between Class A and Class B
 * 	
 */

public enum ClassRelation {
	INHERITANCE(0),
	
	STATIC_ARRAY_FIELD(1),
	STATIC__FIELD(2),
	INSTANCE_ARRAY_FIELD(3),
	INSTANCE_FIELD(4),
	
	METHOD_ARRAY_PARAMERTER(5),
	METHOD_PARAMETER(6),
	METHOD_ARRAY_RETURN(7),
	METHOD_RETURN(8),
	METHOD_ARRAY_LOCAL(9),
	METHOD_LOCAL(10),
	
	STMT_ARRAY_REF(11),
	STMT_INSTANCE_FIELD_REF(12),
	STMT_STATIC_FIELD_REF(13),
	STMT_LOCAL_REF(14),
	
	CAST_EXPR(15),
	INSTANCE_OF_EXPR(16),
	NEW_EXPR(17),
	NEW_ARRAY_EXPR(18),
	NEW_MULTI_ARRAY_EXPR(19),
	
	INVOKE_EXPR(20),
	ICC(21),
	
	IMPL(22),
	OUTER_CLASS(23),
	
	ClassRelationNone(24);
	
	
	private final int index;
	
	private ClassRelation(final int newIndex) {
		index = newIndex;
	}
	
	public int getIndex() {
		return index;
	}
}













