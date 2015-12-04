
/*******************************************************************************
 * This code has been extracted from tree-ssa-structalias.c of GCC. It was
 * refactored by Prashant Singh Rawat. It was further improved by Prachi Yogi,
 * Sudakshina Das, Swati Rathi, Avantika Gupta, Pritam Gharat, and of course
 * me (Vini) and then there were three more Ahzaz, Anshuman, Komal ;-)
 *******************************************************************************/


#include "parser.hh"

// Whether or not to split blocks containing pointer dereferences
#define SPLIT_DEREF 1

// Supratik sir needs points-to information at each block. So we keep only one
// statement per block and print points-to information at IN of each block.
#define SPLIT_ALL 1

// Perform name based merging if the program point is a loop join
#define LOOP_MERGE_OPTIMIZATION 0

#define DEBUG_CONTAINER 0
//#define DEBUG(...) fprintf (dump_file, __VA_ARGS__)
#define DEBUG(...) fprintf (stderr, __VA_ARGS__)
#define DDEBUG(...) fprintf (stderr, __VA_ARGS__)
// #define RESULT(...) fprintf (stderr, __VA_ARGS__) //KO
#define DEBUGA(...) {fprintf (stderr, __VA_ARGS__); fflush(stderr);}
//#define DEBUG(...)
#define CERR(A) std::cerr << std::endl << #A << std::endl
//AN
parser::
parser ()
{
	main_cnode = NULL;
	multi_rhs = false;
	compute_only_pinfo = false;
	compute_alias_and_pinfo = false;
	all_contexts_together = true;
	check_deref = false;
	deref_stmt = false;
}
//AN
void parser::
map_arguments_at_call (gimple stmt, tree decl, bool generate_liveness, basic_block bb, struct cgraph_node * cnode)
{
	DEBUG ("\nmap_arguments_at_call");

	vector<ce_s> rhsc;
	// rhsc.create (200);
	// VEC(ce_s, heap) *rhsc = NULL;
	size_t j;
	int argoffset = 1;
	csvarinfo_t fi;

	/* Generate liveness for call via function pointers and library routines. */
	if (generate_liveness) {
		DEBUG ("\nGenerate liveness for function pointers and library routines");

		struct constraint_expr *exp;
		unsigned i;

		for (j = 0; j < gimple_call_num_args (stmt); j++) {
			DEBUG ("\nMapping argument %d", j);
			tree arg = gimple_call_arg (stmt, j);
			if (field_must_have_pointers (arg) && TREE_CODE (arg) != ADDR_EXPR) {
				DEBUG ("\nfield_must_have_pointers");
				vector<ce_s> results;
				cs_get_constraint_for (arg, &results, bb, cnode);
				FOR_EACH_VEC_ELT1 (ce_s, results, i, exp)
				{
					DEBUG ("\nGenerating liveness of variable %d", exp->var);
					((block_information *)(bb->aux))->add_to_parsed_data_indices (exp->var, false, bb);  // generate_liveness_constraints // Vini: Why commented out???
				}
				VEC_free (ce_s, heap, results);
			}
		}
		return;
	}

	/* Map call arguments. */
	fi = cs_get_vi_for_tree (decl, bb, cnode);

	for (j = 0; j < gimple_call_num_args (stmt); j++) {
		struct constraint_expr lhs ;
		// struct constraint_expr *rhsp;
		tree arg = gimple_call_arg (stmt, j);
		if (field_must_have_pointers (arg)) {
			cs_get_constraint_for (arg, &rhsc, bb, cnode);
			lhs.type = SCALAR;
			lhs.var = cs_first_vi_for_offset (fi, argoffset)->id;
			lhs.offset = 0;
			// while (VEC_size (ce_s, rhsc) != 0) {
			while (rhsc.size() != 0) {
				struct constraint_expr &rhsp = rhsc.back(); //VEC_back (ce_s, rhsc);
				DEBUG ("\nmapped arguments:");
				DEBUG ("\nlhs var %d, type %d", lhs.var, lhs.type);
				DEBUG ("\nrhs var %d, type %d", rhsp.var, rhsp.type);
				cs_process_constraint (new_constraint (lhs, rhsp), bb);
				// rhsc.back(); // VEC_pop (ce_s, rhsc);
				rhsc.pop_back();
				multi_rhs = true;
			}
			multi_rhs = false;
		}
		argoffset++;
	}
	rhsc.clear();
	// VEC_free (ce_s, heap, rhsc);

	DEBUG ("\nDone map_arguments_at_call");
}
//AN
//AN // Added by Vini
//AN
//AN void parser::
//AN map_function_pointer_arguments (struct cgraph_node * src_function, basic_block call_site, struct cgraph_node * called_function)
//AN {
//AN    DEBUG ("\nmap_function_pointer_arguments()");
//AN    DEBUG ("\nsrc_function=%s", cgraph_node_name (src_function));
//AN    DEBUG ("\ncalled_function=%s", cgraph_node_name (called_function));
//AN    DEBUG ("\n");
//AN    // FIXME: check that this a call_site has only one statement.
//AN    gimple_stmt_iterator gsi = gsi_start_bb (call_site);
//AN    gimple stmt = gsi_stmt (gsi);
//AN
//AN    VEC(ce_s, heap) *rhsc = NULL;
//AN    size_t j;
//AN    int argoffset = 1;
//AN    csvarinfo_t fi;
//AN
//AN    // Count number of parameters
//AN    unsigned int num = 0;
//AN    for (tree t = DECL_ARGUMENTS (called_function->decl); t; t = DECL_CHAIN (t))
//AN         ++num;
//AN    // Check the number of parameters and arguments. If they are different, then
//AN    // do not perform any mapping.
//AN    if (num != gimple_call_num_args (stmt))
//AN    {
//AN    DEBUG ("\nMapping of src_function and called_function is wrong.");
//AN         VEC_free (ce_s, heap, rhsc);
//AN    return;
//AN    }
//AN
//AN    fi = cs_get_vi_for_tree (called_function->decl, call_site, src_function);
//AN
//AN #if DEBUG_CONTAINER
//AN    DEBUG ("\nFunction call: ");
//AN    print_gimple_stmt (dump_file, stmt, 0, 0);
//AN #endif
//AN
//AN    for (j = 0; j < gimple_call_num_args (stmt); j++) {
//AN        DEBUG ("\narg=%d", j);
//AN        struct constraint_expr lhs ;
//AN        struct constraint_expr *rhsp;
//AN        tree arg = gimple_call_arg (stmt, j);
//AN        if (field_must_have_pointers (arg)) {
//AN            DEBUG ("\narg has pointers");
//AN            cs_get_constraint_for (arg, &rhsc, call_site, src_function);
//AN            lhs.type = SCALAR;
//AN            csvarinfo_t param = cs_first_vi_for_offset (fi, argoffset);
//AN       // Due to wrong function pointer's callee, the number of arguments
//AN       // may not be equal to number of parameters. Return of this is the
//AN       // case.
//AN       if (!param)
//AN            {
//AN                 VEC_free (ce_s, heap, rhsc);
//AN        return;
//AN            }
//AN            lhs.var = param->id;
//AN            lhs.offset = 0;
//AN       DEBUG ("\nmapped arguments:");
//AN           DEBUG ("\nlhs var %d, type %d", lhs.var, lhs.type);
//AN            while (VEC_size (ce_s, rhsc) != 0) {
//AN                rhsp = VEC_back (ce_s, rhsc);
//AN        DEBUG ("\nrhs var %d, type %d", rhsp->var, rhsp->type);
//AN               cs_process_constraint (new_constraint (lhs, *rhsp), call_site);
//AN                VEC_pop (ce_s, rhsc);
//AN                multi_rhs = true;
//AN            }
//AN           multi_rhs = false;
//AN        }
//AN        argoffset++;
//AN    }
//AN    VEC_free (ce_s, heap, rhsc);
//AN
//AN    DEBUG ("\nDone map_arguments_at_call");
//AN }
//AN
//AN /*-------------------------------------------------------------------------------------
//AN   A call statement can return a value. This mapping has to be performed (after the call
//AN   has been made) at the return block.
//AN   ------------------------------------------------------------------------------------*/
//AN void parser::
//AN map_return_value (basic_block call_block, struct cgraph_node * src_function, basic_block end_block, struct cgraph_node * called_function)
//AN {
//AN    DEBUG ("\nmap_return_value");
//AN    bool found_rhs = true;
//AN    /* Is there a receiving pointer value in the call statement? */
//AN    gimple call_stmt = bb_call_stmt (call_block);
//AN #if DEBUG_CONTAINER
//AN    DEBUG ("\nCall sttmt: ");
//AN    print_gimple_stmt (dump_file, call_stmt, 0, 0);
//AN #endif
//AN    if (is_gimple_call (call_stmt))
//AN    {
//AN       tree lhsop = gimple_call_lhs (call_stmt);
//AN       if (lhsop && field_must_have_pointers (lhsop))
//AN       {
//AN          DEBUG ("\nlhs is pointer");
//AN          found_rhs = false;
//AN          gimple_stmt_iterator ret_gsi;
//AN          for (ret_gsi = gsi_start_bb (end_block); !gsi_end_p (ret_gsi); gsi_next (&ret_gsi))
//AN          {
//AN             gimple ret_stmt = gsi_stmt (ret_gsi);
//AN #if DEBUG_CONTAINER
//AN             DEBUG ("\nreturn stmt: ");
//AN             print_gimple_stmt (dump_file, ret_stmt, 0, 0);
//AN #endif
//AN             if (gimple_code (ret_stmt) == GIMPLE_RETURN)
//AN             {
//AN                tree rhsop = gimple_return_retval (ret_stmt);
//AN           if (rhsop != NULL_TREE)
//AN                {
//AN                   /* Map it to the return value of return statement. */
//AN                   VEC(ce_s, heap) *lhsc = NULL, *rhsc = NULL;
//AN                   cs_get_constraint_for (lhsop, &lhsc, call_block, src_function);
//AN                   cs_get_constraint_for (rhsop, &rhsc, end_block, called_function);
//AN                   cs_process_all_all_constraints (lhsc, rhsc, call_block);
//AN                   VEC_free (ce_s, heap, lhsc);
//AN                   VEC_free (ce_s, heap, rhsc);
//AN
//AN          found_rhs = true;
//AN                   break;
//AN                }
//AN        }
//AN          }
//AN       }
//AN    }
//AN    // This may not be an error because a function pointer may be pointing to a
//AN    // wrong (over-approximate) called_function
//AN    if (!found_rhs)
//AN    DEBUG ("\ncall-statement expects return, but return-block not found");
//AN }
//AN
void parser::
process_library_call (gimple stmt, basic_block bb, struct cgraph_node * cnode)
{

	DEBUG ("\nin process lib");
	/* Generate liveness. */
	map_arguments_at_call (stmt, NULL, true, bb, cnode);
	/* Handle malloc by introducing a points to to heap. */
	if (gimple_call_flags (stmt) & ECF_MALLOC) {
		tree lhs = gimple_call_lhs (stmt);
		if (lhs && field_must_have_pointers (lhs))
		{
			csvarinfo_t heap_info = cs_make_constraint_from_heapvar (lhs, "heap", bb, cnode);
			save_heap_location (stmt, heap_info->id);
		}
	}
}
//AN
//AN gimple parser::
//AN bb_call_stmt (basic_block bb)
//AN {
//AN    gimple_stmt_iterator gsi;
//AN    gimple stmt;
//AN    for (gsi = gsi_start_bb (bb); !gsi_end_p (gsi); gsi_next (&gsi)) {
//AN       stmt = gsi_stmt (gsi);
//AN       if (is_gimple_call (stmt))
//AN          return stmt;
//AN    }
//AN    return NULL;
//AN }
//AN
//AN /*-------------------------------------------------
//AN    FUNCTIONS FROM tree-ssa-structalias.c
//AN ---------------------------------------------------*/
//AN
//AN /* Return the position, in bits, of FIELD_DECL from the beginning of its
//AN    structure.  */
//AN
HOST_WIDE_INT parser::
bitpos_of_field (const tree fdecl)
{
	if (!tree_fits_uhwi_p (DECL_FIELD_OFFSET (fdecl))
	        || !tree_fits_uhwi_p (DECL_FIELD_BIT_OFFSET (fdecl)))
		return -1;

	return (TREE_INT_CST_LOW (DECL_FIELD_OFFSET (fdecl)) * BITS_PER_UNIT
	        + TREE_INT_CST_LOW (DECL_FIELD_BIT_OFFSET (fdecl)));
}
//AN
//AN
//AN /* Create a new constraint consisting of LHS and RHS expressions.  */
//AN
constraint_t parser::
new_constraint (const struct constraint_expr lhs,
                const struct constraint_expr rhs)
{
	DEBUG ("\n(constraint_t) pool_alloc (constraint_pool)");
	constraint_t ret = (constraint_t) pool_alloc (constraint_pool);

	ret->lhs = lhs;
	ret->rhs = rhs;
	return ret;
}
//AN
//AN /* Return true if two constraint expressions A and B are equal.  */
//AN
//AN bool parser::
//AN constraint_expr_equal (struct constraint_expr a, struct constraint_expr b)
//AN {
//AN   return a.type == b.type && a.var == b.var && a.offset == b.offset;
//AN }
//AN
//AN /* Return true if two constraints A and B are equal.  */
//AN
//AN bool parser::
//AN constraint_equal (struct constraint a, struct constraint b)
//AN {
//AN   return constraint_expr_equal (a.lhs, b.lhs)
//AN     && constraint_expr_equal (a.rhs, b.rhs);
//AN }
//AN
//AN /* Return a printable name for DECL  */
//AN
const char * parser::
alias_get_name (tree decl)
{
	const char *res = NULL;
	char *temp;
	int num_printed = 0;
	if (!dump_file)
		return "NULL";

	if (TREE_CODE (decl) == SSA_NAME)
	{
		DEBUG ("\n1************************");
		res = get_name (decl);
		if (res)
			num_printed = asprintf (&temp, "%s_%u", res, SSA_NAME_VERSION (decl));
		else
			num_printed = asprintf (&temp, "_%u", SSA_NAME_VERSION (decl));
		if (num_printed > 0)
		{
			res = ggc_strdup (temp);
			free (temp);
		}
	}
	else if (DECL_P (decl))
	{	DEBUG ("\n2************************");
		if (DECL_ASSEMBLER_NAME_SET_P (decl))
			res = IDENTIFIER_POINTER (DECL_ASSEMBLER_NAME (decl));
		else
		{
			res = get_name (decl);
			if (!res)
			{
				num_printed = asprintf (&temp, "D.%u", DECL_UID (decl));
				if (num_printed > 0)
				{
					res = ggc_strdup (temp);
					free (temp);
				}
			}
		}
	}
	if (res != NULL)
		return res;

	return "NULL";
}
//AN
//AN /* Return true if V is a tree that we can have subvars for.
//AN    Normally, this is any aggregate type.  Also complex
//AN    types which are not gimple registers can have subvars.  */
//AN
inline bool parser::
var_can_have_subvars (const_tree v)
{
	/* Volatile variables should never have subvars.  */
	if (TREE_THIS_VOLATILE (v))
	{
		DEBUG ("\ntree_this_volatile");
		return false;
	}

	/* Non decls or memory tags can never have subvars.  */
	if (!DECL_P (v))
	{
		DEBUG ("\n!decl_p");
		return false;
	}

	/* Aggregates without overlapping fields can have subvars.  */
	if (TREE_CODE (TREE_TYPE (v)) == RECORD_TYPE)
	{
		DEBUG ("\nrecord_type");
		return true;
	}

	// FIXME: MEM_REF (for example, *x) can also have subvars

	DEBUG ("\nvar cannot have subvars");
	return false;
}
//AN
//AN /* Return true if T is a type that does contain pointers.  */
//AN
bool parser::
type_must_have_pointers (tree t)
{
	if (POINTER_TYPE_P (t))
	{
		/// DEBUG ("\npointer_type_p");
		return true;
	}

	if (TREE_CODE (t) == ARRAY_TYPE)
	{
		/// DEBUG ("\narray_type");
		return type_must_have_pointers (TREE_TYPE (t));
	}

	/* A function or method can have pointers as arguments, so track
	   those separately.  */
	if (TREE_CODE (t) == FUNCTION_TYPE
	        || TREE_CODE (t) == METHOD_TYPE)
	{
		/// DEBUG ("\nfunction_type or method_type");
		return true;
	}

	// FIXME: Swati: This check is to consider x=y, x=*y, *x=y type of structure
	// assignment statements.
	if (RECORD_OR_UNION_TYPE_P (t))
	{
		/// DEBUG ("\nrecord_or_union_type_p");
		return true;
	}

	// FIXME: To deal with *x=y, x=*y statements, where lhs and/or rhs is not an
	// address.
	//if (TREE_CODE (t) == MEM_REF)
	//{
	//  /// DEBUG ("\nmem_ref");
	//  return true;
	//}

	/// DEBUG ("\ntype does not have pointers");

	return false;
}

//AN
bool parser::
field_must_have_pointers (tree t)
{
	DEBUG ("\nfield_must_have_pointers");
	return type_must_have_pointers (TREE_TYPE (t));
}
//AN
void check (vector<fieldoff_s> *fieldstack )
{
	if (fieldstack->size() <= 1
	        || fieldstack->size() > MAX_FIELDS_FOR_FIELD_SENSITIVE) {
		DEBUG ("\n4** will be executed");
	}
	else
		DEBUG ("\n4** will NOT be executed");
}
//AN
//AN /**
//AN  * Given index of POINTER_RECORD (pointer to a variable), this function returns
//AN  * a vector of field offsets of the variable pointed by POINTER_RECORD.
//AN  */
//AN
//AN VEC (fieldoff_s, heap) * parser::
//AN get_fieldstack (unsigned int pointer_record)
//AN {
//AN         csvarinfo_t var = VEC_index (csvarinfo_t, variable_data, pointer_record);
//AN         // Extract record from pointer_record
//AN         tree type;
//AN         if (var && var->decl && TREE_TYPE (var->decl))
//AN    {
//AN                 type = TREE_TYPE (var->decl);
//AN #if DEBUG_CONTAINER
//AN        DEBUG ("\n============\n");
//AN        print_node_brief (dump_file, "", var->decl, 0);
//AN        DEBUG ("\n------------\n");
//AN        print_node (dump_file, "", type, 0);
//AN        DEBUG ("\n============\n");
//AN #endif
//AN    }
//AN
//AN         VEC (fieldoff_s, heap) * fieldstack = NULL;
//AN         push_fields_onto_fieldstack (type, &fieldstack, 0);
//AN         DEBUG ("\nNumber of fields: %d", VEC_size (fieldoff_s, fieldstack));
//AN
//AN         fieldoff_s * fo = NULL;
//AN         unsigned int j;
//AN         DEBUG ("\nOffsets: ");
//AN         for (j = 0; VEC_iterate (fieldoff_s, fieldstack, j, fo); j++)
//AN         {
//AN                 //if (fo->has_unknown_size || fo->offset < 0)
//AN                         DEBUG ("%s(%lld), ", fo->offset);
//AN         }
//AN
//AN         return fieldstack;
//AN }
//AN
//AN
//AN /* Given a TYPE, and a vector of field offsets FIELDSTACK, push all
//AN    the fields of TYPE onto fieldstack, recording their offsets along
//AN    the way.
//AN
//AN    OFFSET is used to keep track of the offset in this entire
//AN    structure, rather than just the immediately containing structure.
//AN    Returns false if the caller is supposed to handle the field we
//AN    recursed for.  */
//AN
bool parser::
push_fields_onto_fieldstack (tree type, vector<fieldoff_s> *fieldstack, HOST_WIDE_INT offset)
{
	DEBUG ("\npush_fields_onto_fieldstack");
	DEBUG ("\nVEC_size (fieldoff_s, *fieldstack)=%d", fieldstack->size());
	unsigned int i = 0;
	fieldoff_s *fo = NULL;
	FOR_EACH_VEC_ELT (*fieldstack, i, fo)
	{
		DEBUG ("%lld,", fo->offset);
	}

	tree field;
	bool empty_p = true;

	if (TREE_CODE (type) != RECORD_TYPE)
		return false;

	DEBUG ("\npush_fields 1--");

	/* If the vector of fields is growing too big, bail out early.
	   Callers check for VEC_size <= MAX_FIELDS_FOR_FIELD_SENSITIVE, make
	   sure this fails.  */
	// FIXME: Vini: We have not handled the case when a structure has more than
	// MAX_FIELDS_FOR_FIELD_SENSITIVE number of fields, i.e. we do not perform
	// safe field insensitive analysis in this case. It would be better to
	// terminate in such a case, or not put such a restriction at all.
	if (fieldstack->size() > MAX_FIELDS_FOR_FIELD_SENSITIVE)
		return false;

	DEBUG ("\npush_fields 2--");

	// FIXME: Vini: Create a list of field dereferences in this loop

	for (field = TYPE_FIELDS (type); field; field = DECL_CHAIN (field))
		if (TREE_CODE (field) == FIELD_DECL)
		{
			DEBUG ("\npush_fields 3--");
			DEBUG ("\nField %s in loop", get_name (field));
			bool push = false;
			HOST_WIDE_INT foff = bitpos_of_field (field);
			DEBUG ("\nfoff=%d", foff);

			if (!var_can_have_subvars (field)
			        || TREE_CODE (TREE_TYPE (field)) == QUAL_UNION_TYPE
			        || TREE_CODE (TREE_TYPE (field)) == UNION_TYPE)
			{
				DEBUG ("\n!var_can_have_subvars");
				push = true;
			}
			else if (!push_fields_onto_fieldstack
			         (TREE_TYPE (field), fieldstack, offset + foff)
			         && (DECL_SIZE (field)
			             && !integer_zerop (DECL_SIZE (field))))
			{
				/* Empty structures may have actual size, like in C++.  So
				   see if we didn't push any subfields and the size is
				   nonzero, push the field onto the stack.  */
				DEBUG ("\npush_fields 4--");
				check (fieldstack);
				push = true;
			}
			DEBUG ("\nField %s has push=%d", get_name (field), push);

			if (push)
			{
				DEBUG ("\npush_fields 5--");
				DEBUG ("\nField %s to be pushed", get_name (field));
				fieldoff_s *pair = NULL;
				bool has_unknown_size = false;
				bool must_have_pointers_p;

				DEBUG ("\nVEC_empty (fieldoff_s, *fieldstack)=%d, VEC_size (fieldoff_s, *fieldstack)=%d",
				       fieldstack->size() == 0, fieldstack->size());
				// VEC_empty (fieldoff_s, *fieldstack), VEC_size (fieldoff_s, *fieldstack));
				// if (!VEC_empty (fieldoff_s, *fieldstack))
				if (!fieldstack->size() == 0)
				{
					DEBUG ("\npush_fields 6--");
					DEBUG ("\nField %s 6--", get_name (field));
					check (fieldstack);
					pair = &(fieldstack->back()); //VEC_back (fieldoff_s, *fieldstack);
				}

				DEBUG ("\noffset=%lld, foff=%lld", offset, foff);
				/* If there isn't anything at offset zero, create sth.  */
				if (!pair
				        && offset + foff != 0)
				{
					DEBUG ("\npush_fields 7--");
					DEBUG ("\nField %s 7--", get_name (field));
					DEBUG ("\nbefore VEC_size (fieldoff_s, *fieldstack)=%d", fieldstack->size()); //VEC_size (fieldoff_s, *fieldstack));
					fieldoff_s null;
					fieldstack->push_back(null);
					pair = &(fieldstack->back()); //VEC_push_back (fieldoff_s, heap, *fieldstack, NULL);
					pair->offset = 0;
					pair->size = offset + foff;
					pair->has_unknown_size = false;
					pair->must_have_pointers = false;
					pair->may_have_pointers = false;
					pair->only_restrict_pointers = false;
					DEBUG ("\nafter VEC_size (fieldoff_s, *fieldstack)=%d", fieldstack->size()); //VEC_size (fieldoff_s, *fieldstack));
					DEBUG ("\npair->offset=%lld", pair->offset);
					DEBUG ("\n7-- pushed fields:");
					unsigned int i = 0;
					fieldoff_s *fo = NULL;
					FOR_EACH_VEC_ELT (*fieldstack, i, fo)
					{
						DEBUG ("%lld,", fo->offset);
					}

				}
				if (!DECL_SIZE (field)
				        || !tree_fits_uhwi_p (DECL_SIZE (field)))
				{
					DEBUG ("\npush_fields 8--");
					DEBUG ("\nField %s 8--", get_name (field));
					has_unknown_size = true;
				}
#if DEBUG_CONTAINER
				else
				{
					DEBUG ("\npush_fields 9--");
					DEBUG ("\nField %s 9--", get_name (field));
				}
#endif
				check (fieldstack);

				/* If adjacent fields do not contain pointers merge them.  */
				must_have_pointers_p = field_must_have_pointers (field);
				if (pair
				        && !has_unknown_size
				        && !must_have_pointers_p
				        && !pair->must_have_pointers
				        && !pair->has_unknown_size
				        && pair->offset + (HOST_WIDE_INT)pair->size == offset + foff)
				{
					DEBUG ("\npush_fields 10--");
					DEBUG ("\nField %s 10--", get_name (field));
					pair->size += TREE_INT_CST_LOW (DECL_SIZE (field));
				}
				else
				{
					DEBUG ("\npush_fields 11--");
					DEBUG ("\nField %s 11--", get_name (field));
					DEBUG ("\nbefore VEC_size (fieldoff_s, *fieldstack)=%d", fieldstack->size());
					check (fieldstack);
					fieldoff_s null;
					fieldstack->push_back(null);
					pair = &(fieldstack->back()); //VEC_push_back (fieldoff_s, heap, *fieldstack, NULL); // PROBLEM: fieldstack not working
					check (fieldstack);
					pair->offset = offset + foff;
					pair->has_unknown_size = has_unknown_size;
					if (!has_unknown_size)
						pair->size = TREE_INT_CST_LOW (DECL_SIZE (field));
					else
						pair->size = -1;
					pair->must_have_pointers = must_have_pointers_p;
					pair->may_have_pointers = true;
					pair->only_restrict_pointers
					    = (!has_unknown_size
					       && POINTER_TYPE_P (TREE_TYPE (field))
					       && TYPE_RESTRICT (TREE_TYPE (field)));
					DEBUG ("\nafter VEC_size (fieldoff_s, *fieldstack)=%d", fieldstack->size()); //VEC_size (fieldoff_s, *fieldstack));
					DEBUG ("\npair->offset=%lld", pair->offset);
					DEBUG ("\n11-- pushed fields:");
					unsigned int i = 0;
					fieldoff_s *fo = NULL;
					// FOR_EACH_VEC_ELT (fieldoff_s, *fieldstack, i, fo)
					FOR_EACH_VEC_ELT (*fieldstack, i, fo)
					{
						DEBUG ("i=%d,%lld,", i, fo->offset);
					}
				}
				DEBUG ("\npush_fields 12--");
				DEBUG ("\nField %s 12--", get_name (field));
				check (fieldstack);
			}

			DEBUG ("\npush_fields 13--");
			DEBUG ("\nField %s 13--", get_name (field));
			check (fieldstack);
			empty_p = false;
		}

	return !empty_p;
}
//AN
//AN tree parser::
//AN get_decl (csvarinfo_t var)
//AN {
//AN    tree root_decl = var->decl;
//AN    HOST_WIDE_INT var_offset = var->offset;
//AN
//AN    DEBUG ("\nget_decl (%s, %lld)", var->name, var_offset);
//AN    // DEBUG ("\nroot: ");
//AN    // print_node (dump_file, 0, root_decl, 0);
//AN
//AN    return get_decl_private (root_decl, 0, var_offset);
//AN }
//AN
//AN /**
//AN  * Given VAR tree and VAR_OFFSET, which is its offset position from its
//AN  * outermost structure, this function returns the tree declaration which is at
//AN  * SEARCH_OFFSET position from its outermost structure.
//AN  */
//AN
//AN tree parser::
//AN get_decl_private (tree var_decl, HOST_WIDE_INT var_offset, HOST_WIDE_INT search_offset)
//AN {
//AN    if (var_offset == search_offset)
//AN    {
//AN        DEBUG ("\nFound=%lld", search_offset);
//AN        // print_node (dump_file, 0, var_decl, 0);
//AN        return var_decl;
//AN    }
//AN
//AN    if (!TREE_TYPE (var_decl) || !RECORD_OR_UNION_TYPE_P (TREE_TYPE (var_decl)))
//AN        return NULL;
//AN
//AN    for (tree field = TYPE_FIELDS (TREE_TYPE (var_decl)); field; field = TREE_CHAIN (field))
//AN    {
//AN        if (TREE_CODE (field) == FIELD_DECL)
//AN        {
//AN            HOST_WIDE_INT field_offset = bitpos_of_field (field);
//AN            DEBUG ("\nfield %s, field_offset=%lld, var+field offset=%lld",
//AN                get_name (field), field_offset, var_offset + field_offset);
//AN            tree ret = get_decl_private (field, var_offset + field_offset, search_offset);
//AN            if (ret)
//AN                return ret;
//AN        }
//AN    }
//AN    return NULL;
//AN }
//AN
//AN /**
//AN  * This function returns field variables inside structure VAR.
//AN  */
//AN
//AN set<unsigned int> parser::
//AN get_reachable_fields (csvarinfo_t var)
//AN {
//AN    DEBUG ("\nget_reachable_fields (%s)", var->name);
//AN    // DEBUG ("\nroot: ");
//AN    // print_node (dump_file, 0, root, 0);
//AN
//AN    tree var_decl = get_decl (var);
//AN
//AN    csvarinfo_t root = program.cs_lookup_vi_for_tree (var->decl);
//AN
//AN    set<unsigned int> reachable_fields;
//AN
//AN    DEBUG ("\nget_reachable_fields_private (%s(%d), var->offset=%lld)",
//AN        root->name, root->id, var->offset);
//AN    get_reachable_fields_private (root, var_decl, var->offset, reachable_fields);
//AN
//AN    return reachable_fields;
//AN }
//AN
//AN /**
//AN  * Given a structure VAR_DECL at address VAR_OFFSET from ROOT, this function
//AN  * finds member fields that are immediately inside this structure. Note that
//AN  * the member fields of the non-pointer first field of every structure are
//AN  * considered as immediately nested.
//AN  */
//AN
//AN void parser::
//AN get_reachable_fields_private (csvarinfo_t root, tree var_decl, HOST_WIDE_INT var_offset, set<unsigned int> & reachable_fields)
//AN {
//AN    if (!TREE_TYPE (var_decl) || !RECORD_OR_UNION_TYPE_P (TREE_TYPE (var_decl)))
//AN        return;
//AN
//AN    for (tree field = TYPE_FIELDS (TREE_TYPE (var_decl)); field; field = TREE_CHAIN (field))
//AN    {
//AN        if (TREE_CODE (field) == FIELD_DECL)
//AN        {
//AN            HOST_WIDE_INT field_offset = bitpos_of_field (field);
//AN            DEBUG ("\n%s, offset=%lld", get_name (var_decl), field_offset);
//AN            csvarinfo_t field_var =
//AN                cs_first_vi_for_offset (root, var_offset + field_offset);
//AN            if (!field_var)
//AN            {
//AN                RESULT ("\nError: cs_first_vi_for_offset (%s(%d), offset=%lld) not found",
//AN                    root->name, root->id, var_offset + field_offset);
//AN                continue;
//AN            }
//AN            DEBUG ("\nfield %s, field_offset=%lld, root+field offset=%lld -- var=%s(%d)",
//AN                get_name (field), field_offset, var_offset + field_offset,
//AN                field_var->name, field_var->id);
//AN            reachable_fields.insert (field_var->id);
//AN
//AN            // If FIELD is the first field of the structure at
//AN            // VAR_OFFSET, then the member fields of FIELD are also
//AN            // REACHABLE_FIELDS of the structure at VAR_OFFSET.
//AN            if (!field_offset)
//AN                get_reachable_fields_private
//AN                    (root, field, var_offset + field_offset, reachable_fields);
//AN        }
//AN    }
//AN }
//AN
//AN /* Count the number of arguments DECL has, and set IS_VARARGS to true
//AN    if it is a varargs function.  */
//AN
unsigned int parser::
count_num_arguments (tree decl, bool *is_varargs)
{
	unsigned int num = 0;
	tree t;

	/* Capture named arguments for K&R functions.  They do not
	   have a prototype and thus no TYPE_ARG_TYPES.  */
	for (t = DECL_ARGUMENTS (decl); t; t = DECL_CHAIN (t))
		++num;

	/* Check if the function has variadic arguments.  */
	for (t = TYPE_ARG_TYPES (TREE_TYPE (decl)); t; t = TREE_CHAIN (t))
		if (TREE_VALUE (t) == void_type_node)
			break;
	if (!t)
		*is_varargs = true;

	return num;
}
//AN
//AN /* Return true if FIELDSTACK contains fields that overlap.
//AN    FIELDSTACK is assumed to be sorted by offset.  */
//AN
bool parser::
check_for_overlaps (vector<fieldoff_s> &fieldstack)
{
	fieldoff_s *fo = NULL;
	unsigned int i;
	HOST_WIDE_INT backoffset = -1;

	//AH FOR_EACH_VEC_ELT (fieldoff_s, fieldstack, i, fo)
	FOR_EACH_VEC_ELT (fieldstack, i, fo)
	{
		if (fo->offset == backoffset)
			return true;
		backoffset = fo->offset;
	}
	return false;
}
//AN
//AN
//AN /* qsort comparison function for two fieldoff's PA and PB */
//AN // This function cannot be made a member function of this class
//AN
int
// fieldoff_compare (const void *pa, const void *pb)
fieldoff_compare (const fieldoff_s &pa, const fieldoff_s &pb)
{
	const fieldoff_s *foa = &pa;
	const fieldoff_s *fob = &pb;
	// const fieldoff_s *foa = (const fieldoff_s *)pa;
	// const fieldoff_s *fob = (const fieldoff_s *)pb;
	unsigned HOST_WIDE_INT foasize, fobsize;

	if (foa->offset < fob->offset)
		return -1;
	else if (foa->offset > fob->offset)
		return 1;

	foasize = foa->size;
	fobsize = fob->size;
	if (foasize < fobsize)
		return -1;
	else if (foasize > fobsize)
		return 1;
	return 0;
}
//AN
//AN /* Sort a fieldstack according to the field offset and sizes.  */
void parser::
sort_fieldstack (vector<fieldoff_s> &fieldstack)
{
	//AH VEC_qsort (fieldoff_s, fieldstack, fieldoff_compare);
	sort(fieldstack.begin(), fieldstack.end(),fieldoff_compare);
}
//AN
//AN
//AN /*----------------------------------------------------------------------
//AN   The base implementation. The method implements points-to analysis
//AN   using callstrings method. All the functions that have _cs_
//AN   prepended to their names have been lifted from tree-ssa-structalias.c
//AN   ---------------------------------------------------------------------*/
//AN
//AN /* Return the varmap element N */
csvarinfo_t parser::
cs_get_varinfo (unsigned int n)
{
	return (csvarmap)[n];
	/// return VEC_index (csvarinfo_t, csvarmap, n);
}
//AN
//AN /* Insert ID as the variable id for tree T in the vi_for_tree map.  */
void parser::
cs_insert_vi_for_tree (tree t, csvarinfo_t vi)
{
	DEBUG ("\ncs_insert_vi_for_tree\n");
	//KO void **slot = pointer_map_insert (vi_for_tree, t);
	gcc_assert (vi);
	//KO gcc_assert (*slot == NULL);
	DEBUG ("\ncs_insert_vi_for_tree %d %d %d\n ", vi_for_tree->get(t), t, vi);
	gcc_assert (!vi_for_tree->put (t, vi)); //KO NEWADD
	//KO *slot = vi;
}
//AN
bool parser::
is_proper_var (unsigned int varid)
{
	return (varid > 2);
}
//AN bool parser::
//AN parm_decl (unsigned int varid)
//AN {
//AN    return (TREE_CODE (SSAVAR (cs_get_varinfo (varid)->decl))
//AN      == PARM_DECL);
//AN }
//AN
//AN struct cgraph_node * parser::
//AN scoping_fn (unsigned int varid)
//AN {
//AN    return cs_get_varinfo (varid)->scoping_function;
//AN }
//AN
//AN bool parser::
//AN var_defined_in_cfun (unsigned int varid, struct cgraph_node * cnode)
//AN {
//AN    return (cnode == scoping_fn (varid));
//AN }
//AN
//AN bool parser::
//AN heap_var (unsigned int varid)
//AN {
//AN    return (cs_get_varinfo (varid)->is_heap_var);
//AN }
//AN
//AN
//AN bool parser::
//AN global_var (unsigned int varid)
//AN {
//AN    return (cs_get_varinfo (varid)->is_global_var);
//AN }
//AN
//AN bool parser::
//AN unexpandable_var (unsigned int var, HOST_WIDE_INT offset)
//AN {
//AN    return (offset == 0 ||
//AN            !is_proper_var (var) ||
//AN            offset == UNKNOWN_OFFSET ||
//AN            cs_get_varinfo (var)->is_heap_var);
//AN }
//AN
//AN bool parser::
//AN function_var (csvarinfo_t var)
//AN {
//AN    if (TREE_CODE (TREE_TYPE (var->decl)) == FUNCTION_TYPE
//AN        || TREE_CODE (TREE_TYPE (var->decl)) == METHOD_TYPE)
//AN        return true;
//AN    return false;
//AN }
//AN
//AN bool parser::
//AN parameter_var (csvarinfo_t var)
//AN {
//AN    if (TREE_CODE (var->decl) == PARM_DECL)
//AN        return true;
//AN    return false;
//AN }
//AN
//AN /* Given a gimple tree T, return the constraint expression vector for it
//AN    to be used as the rhs of a constraint.  */
void parser::
// cs_get_constraint_for_rhs (tree t, VEC (ce_s, heap) **results, basic_block bb, struct cgraph_node * cnode)
cs_get_constraint_for_rhs (tree t, vector<ce_s> *results, basic_block bb, struct cgraph_node * cnode)
{
	gcc_assert (results->size() == 0);
	cs_get_constraint_for_1 (t, results, false, false, bb, cnode);
}
//AN
/* Return a new variable info structure consisting for a variable
   named NAME, and using constraint graph node NODE.  Append it
   to the vector of variable info structures.  */
csvarinfo_t parser::
cs_new_var_info (tree t, const char *name, struct cgraph_node * cnode)
{
	unsigned index = csvarmap.size();// VEC_size (csvarinfo_t, csvarmap);
	DEBUG ("\n(csvarinfo_t) pool_alloc (csvarinfo_pool)");
	csvarinfo_t ret = (csvarinfo_t) pool_alloc (csvarinfo_pool);
	DEBUG ("\ncs_new_var_info index: %d, %s", index, name);
	DEBUG ("\nis_full_var = %d", t == NULL_TREE);

	ret->id = index;
	ret->name = name;
	ret->decl = t;
	ret->is_unknown_size_var = false;
	ret->is_full_var = (t == NULL_TREE);
	ret->is_heap_var = false;
	ret->may_have_pointers = true;
	ret->is_global_var = (t == NULL_TREE);
	/* Vars without decl are artificial and do not have sub-variables.  */
	if (t && DECL_P (t))
		ret->is_global_var = (is_global_var (t)
		                      /* We have to treat even local register variables
		                         as escape points.  */
		                      || (TREE_CODE (t) == VAR_DECL
		                          && DECL_HARD_REGISTER (t)));
	//ret->constraints_with_vi_as_lhs = NULL;
	ret->scoping_function = (ret->is_global_var) ? NULL : cnode;
	ret->next = NULL;

	// VEC_push_back (csvarinfo_t, heap, csvarmap, ret);
	csvarmap.push_back(ret);
	DEBUG ("\ncs_new_var_info done");
	return ret;
}
//AN
//AN /* Create a varinfo structure for NAME and DECL, and add it to VARMAP.
//AN    This will also create any varinfo structures necessary for fields
//AN    of DECL.  */
csvarinfo_t parser::
cs_create_variable_info_for_1 (tree decl, const char *name, struct cgraph_node * cnode)
{
	DEBUG ("\ncs_create_variable_info_for_1");
	DEBUG ("\nCreating var %s", name);
	csvarinfo_t vi, newvi;
	DEBUG ("\n1******************************************************************%d\n", decl);
	tree decl_type = TREE_TYPE (decl); // decl=VAR_DECL, decl_type=RECORD_TYPE
	tree declsize = DECL_P (decl) ? DECL_SIZE (decl) : TYPE_SIZE (decl_type);
	vector<fieldoff_s> fieldstack; // VEC (fieldoff_s,heap) *fieldstack = NULL;
	// fieldoff_s *fo;
	unsigned int i;
	varpool_node *vnode;

	if (!declsize || !tree_fits_uhwi_p (declsize)) {
		DEBUG ("\nis_full_var 1 for %s, %s", get_name (decl), name);
		vi = cs_new_var_info (decl, name, cnode);
		vi->offset = 0;
		vi->size = ~0;
		vi->fullsize = ~0;
		vi->is_unknown_size_var = true;
		vi->is_full_var = true;
		vi->may_have_pointers = true;
		return vi;
	}
	DEBUG ("\n2******************************************************************\n");
	/* Collect field information.  */
	if (var_can_have_subvars (decl)
	        /* ???  Force us to not use subfields for global initializers
	        in IPA mode.  Else we'd have to parse arbitrary initializers.  */
	        && !(is_global_var (decl) && (vnode = varpool_node::get (decl))
	             && vnode->get_constructor ())) {

		DEBUG ("\nglobal variable 2: ");
		// print_node (dump_file, "", DECL_INITIAL (decl), 0);
		DEBUG ("\nis_full_var 2 for %s, %s", get_name (decl), name);
		// fieldoff_s *fo = NULL;
		bool notokay = false;
		unsigned int i;

		push_fields_onto_fieldstack (decl_type, &fieldstack, 0);

		// if (VEC_size (fieldoff_s, fieldstack) <= 1
		//    || VEC_size (fieldoff_s, fieldstack) > MAX_FIELDS_FOR_FIELD_SENSITIVE) {
		if (fieldstack.size() <= 1
		        || fieldstack.size() > MAX_FIELDS_FOR_FIELD_SENSITIVE) {
			DEBUG ("\n4-- will be executed");
		}
		else
			DEBUG ("\n4-- will NOT be executed");

		if (fieldstack.size() <= 1)
			DEBUG ("\n<=1");
		if (fieldstack.size() > MAX_FIELDS_FOR_FIELD_SENSITIVE)
			DEBUG ("\n> MAX_FI... %d", MAX_FIELDS_FOR_FIELD_SENSITIVE);
		else
			DEBUG ("\n< MAX_FI... %d", MAX_FIELDS_FOR_FIELD_SENSITIVE);

		// for (i = 0; !notokay && VEC_iterate (fieldoff_s, fieldstack, i, fo); i++)
		// for (i = 0; !notokay && fieldstack.iterate(i, &fo); i++)
		for (vector<fieldoff_s>::iterator fo = fieldstack.begin(); !notokay && fo != fieldstack.end(); ++fo) //!notokay && fieldstack.iterate(i, &fo); i++)
			if (fo->has_unknown_size || fo->offset < 0) {
				notokay = true;
				break;
			}

		/* We can't sort them if we have a field with a variable sized type,
		which will make notokay = true.  In that case, we are going to return
		without creating varinfos for the fields anyway, so sorting them is a
		waste to boot.  */
		if (!notokay) {

			DEBUG ("\nis_full_var 3 for %s, %s", get_name (decl), name);
			sort_fieldstack (fieldstack);
			/* Due to some C++ FE issues, like PR 22488, we might end up
			   what appear to be overlapping fields even though they,
			   in reality, do not overlap.  Until the C++ FE is fixed,
			   we will simply disable field-sensitivity for these cases.  */
			notokay = check_for_overlaps (fieldstack);
		}

		if (notokay)
			fieldstack.clear(); // VEC_free (fieldoff_s, heap, fieldstack);

	}
	DEBUG ("\n3******************************************************************\n");
	if (fieldstack.size() <= 1) //if (VEC_size (fieldoff_s, fieldstack) <= 1)
		DEBUG ("\n<=1");
	if (fieldstack.size() > MAX_FIELDS_FOR_FIELD_SENSITIVE) //if (VEC_size (fieldoff_s, fieldstack) > MAX_FIELDS_FOR_FIELD_SENSITIVE)
		DEBUG ("\n> MAX_FI... %d", MAX_FIELDS_FOR_FIELD_SENSITIVE);
	else
		DEBUG ("\n< MAX_FI... %d", MAX_FIELDS_FOR_FIELD_SENSITIVE);


	/* If we didn't end up collecting sub-variables create a full
	   variable for the decl.  */
	// MAX_FIELDS_FOR_FIELD_SENSITIVE is set to 0 if gcc is run with -O0 flag.
	// It is set to 100 on my machine when gcc is run with -O3 flag.
	// FIXME: Vini: A structure with only field has VEC_size = 1; therefore,
	// should we modify the check to <= 0
	/// if (VEC_size (fieldoff_s, fieldstack) <= 1
	///    || VEC_size (fieldoff_s, fieldstack) > MAX_FIELDS_FOR_FIELD_SENSITIVE) {
	if (fieldstack.size() <= 1
	        || fieldstack.size() > MAX_FIELDS_FOR_FIELD_SENSITIVE) {

		DEBUG ("\nis_full_var 4 for %s, %s", get_name (decl), name);
		vi = cs_new_var_info (decl, name, cnode);
		vi->offset = 0;
		vi->may_have_pointers = true;
		vi->fullsize = TREE_INT_CST_LOW (declsize);
		vi->size = vi->fullsize;
		vi->is_full_var = true;
		// VEC_free (fieldoff_s, heap, fieldstack);
		fieldstack.clear();
		return vi;
	}

	DEBUG ("\nis_full_var 5 for %s, %s", get_name (decl), name);

	// FIXME: the non-pointer subfields are also stored. These should
	// not be considered.
	vi = cs_new_var_info (decl, name, cnode);
	vi->fullsize = TREE_INT_CST_LOW (declsize);
	// for (i = 0, newvi = vi;
	//         // VEC_iterate (fieldoff_s, fieldstack, i, fo);
	//         fieldstack.iterate(i, &fo);
	//         ++i, newvi = newvi->next) {
	newvi = vi;
	for (vector<fieldoff_s>::iterator fo = fieldstack.begin() ; fo != fieldstack.end(); newvi = newvi->next, ++fo) {

		DEBUG ("\nis_full_var 6 %s, %s\n", get_name (decl), name);

		const char *newname = "NULL";
		char *tempname;

		if (dump_file) {
			asprintf (&tempname, "%s." HOST_WIDE_INT_PRINT_DEC
			          "+" HOST_WIDE_INT_PRINT_DEC, name, fo->offset, fo->size);
			newname = ggc_strdup (tempname);
			free (tempname);

			DEBUG ("\nnewname %s", newname);
		}
		DEBUG ("\noffset %llu, size %d", fo->offset, fo->size);
		newvi->name = newname;
		newvi->offset = fo->offset;
		newvi->size = fo->size;
		newvi->fullsize = vi->fullsize;
		newvi->may_have_pointers = fo->may_have_pointers;
		// Removed by Prashant ??
		// newvi->only_restrict_pointers = fo->only_restrict_pointers;
		// if (i + 1 < VEC_size (fieldoff_s, fieldstack))
		if (i + 1 < fieldstack.size())
			newvi->next = cs_new_var_info (decl, name, cnode);
	}

	// VEC_free (fieldoff_s, heap, fieldstack);
	fieldstack.clear();
	if (vi)
		DEBUG ("\nreturning vi %s, id %d, offset %llu\n", vi->name, vi->id, vi->offset);
	return vi;
}

//AN
unsigned int parser::
cs_create_variable_info_for (tree decl, const char *name, basic_block bb, struct cgraph_node * cnode)
{
	DEBUG ("\ncs_create_variable_info_for\n");
	DEBUG ("\nname %s\n", name);
	csvarinfo_t vi = cs_create_variable_info_for_1 (decl, name, cnode);
	DEBUG ("\ncreated vi %s, id %d, offset %llu\n", vi->name, vi->id, vi->offset);
	unsigned int id = vi->id;

	cs_insert_vi_for_tree (decl, vi);

	/* Create initial constraints for globals.  */
	for (; vi; vi = vi->next) {
		if (!vi->may_have_pointers || !vi->is_global_var)
			continue;

		/// DEBUG ("\nloop -- vi %s, id %d, offset %llu\n", vi->name, vi->id, vi->offset);

		// Vini: DECL_INITIAL (decl) is true only if decl is global variable
		// and it has been initialized with ADDRESSOF globally.
		// FIXME: Here, this global ADDRESSOF constraint is inserted right
		// above the first use of the decl variable. This is wrong. For
		// example,
		// int *global=&v1; int
		// int main() {
		//    if (condition) global=&v2; }
		// The following code will wrongly insert the global constraint
		// inside the if condition, instead of outside it; therefore, v1 will
		// unsafely get overwritten by v2.

		/* If this is a global variable with an initializer,
		generate constraints f2727or it. */
		if (DECL_INITIAL (decl)) {
#if DEBUG_CONTAINER
			/// DEBUG ("\nglobal variable: ");
			//print_node (dump_file, "", decl, 0);
			/// DEBUG ("\nDECL_INITIAL(decl): ");
			//print_node (dump_file, "", DECL_INITIAL (decl), 0);
#endif
			vector<ce_s> rhsc; // VEC (ce_s, heap) *rhsc = NULL;
			struct constraint_expr lhs, *rhsp;
			unsigned i;
			cs_get_constraint_for_rhs (DECL_INITIAL (decl), &rhsc, bb, cnode);
			lhs.var = vi->id;
			lhs.offset = 0;
			lhs.type = SCALAR;
			FOR_EACH_VEC_ELT (rhsc, i, rhsp)/// FOR_EACH_VEC_ELT (ce_s, rhsc, i, rhsp)   // Vini: Why commented out????
			cs_process_constraint (new_constraint (lhs, *rhsp), bb);
			rhsc.clear(); // VEC_free (ce_s, heap, rhsc);     // Vini: Why commented out????
		}
	}

	/// DEBUG ("\nreturn of cs_create_variable_info_for id %d\n", id);
	return id;
}

//AN
//AN /**
//AN  * Find the variable id for tree T in the map. If T doesn't exist in the map,
//AN  * create an entry for it and return it. Use cs_lookup_vi_for_tree if you do
//AN  * not want to create a new csvarinfo_t.
//AN  */
//AN
csvarinfo_t parser::
cs_get_vi_for_tree (tree stmt, basic_block bb, struct cgraph_node * cnode)
{
	DEBUG ("\ncs_get_vi_for_tree");
	// tree t = SSAVAR (stmt); //KO
	tree t = stmt;//KO new add
	// void **slot = pointer_map_contains (vi_for_tree, t);
	csvarinfo_t* slot = vi_for_tree->get(t);
	if (slot == NULL)
	{
		DEBUG ("\nslot == NULL");

		csvarinfo_t vi = cs_get_varinfo (cs_create_variable_info_for (t, alias_get_name (t), bb, cnode));
		DEBUG ("\ncs_get_vi_for_tree");
#if DEBUG_CONTAINER
		if (vi)
			DEBUG ("\nIN cs_get_vi_for_tree: vi %s, id %d, offset %llu\n", vi->name, vi->id, vi->offset);
#endif
		return vi;
		//return cs_get_varinfo (cs_create_variable_info_for (t, alias_get_name (t), bb, cnode));
	}
	DEBUG ("\n*******************");
#if DEBUG_CONTAINER
	csvarinfo_t vi = (csvarinfo_t) * slot;
	if (vi)
		DEBUG ("\nslot %s, offset %llu\n", vi->name, vi->offset);
#endif

	return (csvarinfo_t) * slot;
}
//AN
//AN /* Find the variable info for tree T in VI_FOR_TREE. If T does not
//AN    exist in the map, return NULL, otherwise, return the varinfo
//AN    we found.  */
csvarinfo_t parser::
cs_lookup_vi_for_tree (tree t)
{
	csvarinfo_t *slot = vi_for_tree->get(t);
	if (slot == NULL)
		return NULL;

	return (csvarinfo_t) * slot;
}
//AN
//AN /* Get a scalar constraint expression for a new temporary variable.  */
struct constraint_expr parser::
cs_new_scalar_tmp_constraint_exp (const char *name, struct cgraph_node * cnode)
{
	struct constraint_expr tmp;
	csvarinfo_t vi;

	vi = cs_new_var_info (NULL_TREE, name, cnode);
	vi->offset = 0;
	vi->size = -1;
	vi->fullsize = -1;
	vi->is_full_var = 1;

	tmp.var = vi->id;
	tmp.type = SCALAR;
	tmp.offset = 0;

	return tmp;
}
//AN
//AN /* Sudakshina: CHANGE DUE TO GCC-4.7.2
//AN    function make_heapvar_for of gcc-4.6.* is modified to make_heapvar in gcc-4.7.2.
//AN    This cs_make_heapvar_for is also modified */
//AN
/* Temporary storage for fake var decls.  */
struct obstack fake_var_decl_obstack;
//AN
//AN /* Build a fake VAR_DECL acting as referrer to a DECL_UID.  */
//AN
tree parser::
build_fake_var_decl (tree type)
{
	tree decl = (tree) XOBNEW (&fake_var_decl_obstack, struct tree_var_decl);
	memset (decl, 0, sizeof (struct tree_var_decl));
	TREE_SET_CODE (decl, VAR_DECL);
	TREE_TYPE (decl) = type;
	DECL_UID (decl) = allocate_decl_uid ();
	SET_DECL_PT_UID (decl, -1);
	layout_decl (decl, 0);
	return decl;
}
//AN
//AN /**
//AN  * MEM[...] contains type casted value of the pointer. MEM_REF appears when
//AN  * test.c is compiled with -O3 option.
//AN  * This function returns the inside of POINTER_TYPE ptr, which is used as
//AN  * MEM_REF (typecasted) in PTR_USE.
//AN  */
//AN
tree parser::
get_memref_casted_inside_type (tree ptr_use, tree ptr)
{
	DEBUG ("\nget_memref_casted_inside_type");
	// print_node (dump_file, 0, ptr_use, 0);
	// PTR may have MEM[...]
	tree top = ptr_use;
	// PTR may have &MEM[...]
	if (TREE_CODE (ptr_use) == ADDR_EXPR)
	{
		DEBUG ("\nptr_use is ADDR_EXPR");
		top = TREE_OPERAND (ptr_use, 0);
	}
	tree subtree = top;
	if (TREE_CODE (top) == COMPONENT_REF)
	{
		DEBUG ("\nptr_use has COMPONENT_REF");
		tree subtree = TREE_OPERAND (top, 0);
		// PTR may have multiple COMPONENT_REF. For example,
		// MEM[...].f.g has two COMPONENT_REF.
		return get_memref_casted_inside_type (subtree, ptr);
	}
	if (TREE_CODE (subtree) == MEM_REF)
	{
		DEBUG ("\nptr_use has MEM_REF");
		// We desire to find the casted type of PTR. Check that PTR is
		// actually inside USE_PTR (i.e. in this subtree).
		tree arg0 = TREE_OPERAND (subtree, 0);
		if (arg0 != ptr)
		{
			// This case arises in test43.c where MEM[t1]=MEM[t2].
			// We want to find t2 but we are exploring lhs.
			DEBUG ("\nLooking into wrong MEM_REF");
			return NULL;
		}
		// x=... is not being handled in this function:
		// get_memref_casted_inside_type().  LHS is MEM_REF, which is
		// DEREF type. TREE_OPERAND(0) of MEM_REF is ADDR_EXPR type.
		// This means LHS is SCALAR.  Therefore, type of LHS is
		// TREE_TYPE(MEM_REF). Therefore, type of heap pointed by LHS
		// is TREE_TYPE(TREE_TYPE(MEM_REF)).  However, since
		// TREE_OPERAND(0) cannot be PTR, we are not handling it here.
		// x=x.0_1 (test20.c)
		// MEM[...]
		// This is MEM_REF, which is DEREF type. TREE_OPERAND(0) of
		// MEM_REF is non ADDR_EXPR type. This means it is DEREF.
		// Therefore, its type is POINTER_TYPE containing
		// TREE_TYPE(MEM_REF). Therefore, type of heap pointed by it is
		// TREE_TYPE(MEM_REF).
		// &MEM[(struct node *)v].g (test31i.c)
		// MEM[(struct node **)p]=... (test31i.c)
		tree tree_type = TREE_TYPE (subtree);
		if (TREE_CODE (tree_type) != VOID_TYPE)
		{
			DEBUG ("\nFound type in ptr_use");
			// print_node (dump_file, 0, ptr_use, 0);
			return tree_type;
		}
	}
	return NULL;
}
//AN
//AN /**
//AN  * This function returns the inside of POINTER_TYPE ptr if it is not VOID_TYPE.
//AN  */
//AN
tree parser::
get_inside_type (tree ptr)
{
	// If PTR is COMPONENT_REF or MEM_REF, then the casted type is
	// available. First TREE_TYPE() is used to get one level down from
	// COMPONENT_REF/MEM_REF. TREE_TYPE(TREE_TYPE()) is used to remove
	// POINTER_TYPE in order to return the inside of PTR.
	if (TREE_CODE (ptr) == COMPONENT_REF || TREE_CODE (ptr) == MEM_REF)
	{
		DEBUG ("\nptr is COMPONENT_REF|MEM_REF");
		tree tt = TREE_TYPE (ptr);
		if (tt && TREE_CODE (tt) == POINTER_TYPE)
		{
			DEBUG ("Computed type from indirect lhs");
			// print_node (dump_file, 0, TREE_TYPE (TREE_TYPE (ptr)), 0);
			return TREE_TYPE (TREE_TYPE (ptr));
		}
		else
		{
			RESULT ("\nError: We have reached a non-pointer.");
			return NULL;
		}
	}

	DEBUG ("\nptr = %s: ", get_name (ptr));
	// print_node (dump_file, 0, ptr, 0);
	tree ptr_decl = SSAVAR (ptr);
	if (!ptr_decl)  return NULL;
	DEBUG ("\nptr_decl: ");
	// print_node (dump_file, 0, ptr_decl, 0);
	tree ptr_pointer = TREE_TYPE (ptr_decl);
	if (!ptr_pointer) return NULL;
	DEBUG ("\nptr_pointer: ");
	// print_node (dump_file, 0, ptr_pointer, 0);
	tree ptr_type = TREE_TYPE (ptr_pointer);
	if (!ptr_type) return NULL;
	DEBUG ("\nptr_type: ");
	if (TREE_CODE (ptr_type) == VOID_TYPE) return NULL;

	DEBUG ("\nFound type in ptr");
	DEBUG ("Computed type from direct lhs");
	// print_node (dump_file, 0, ptr_type, 0);
	return ptr_type;
}
//AN
//AN /**
//AN  * This function returns the type inside POINTER_TYPE if PTR is not of 'void *'
//AN  * type. Otherwise it traverses the SSA use-chains to find and return the
//AN  * inside of the casted type of PTR. Note that this function is called to find
//AN  * the type of heap location which needs the inside of POINTER_TYPE created by
//AN  * malloc().
//AN  */
//AN
tree parser::
get_casted_inside_type (tree ptr)
{
	DEBUG ("\nget_casted_inside_type()");

	// Get inside of POINTER_TYPE ptr if a non-VOID_TYPE is already
	// present.
	tree inside_type = get_inside_type (ptr);
	if (inside_type)
		return inside_type;

	// If ptr is not SSA_NAME, then we cannot find its type
	if (TREE_CODE (ptr) != SSA_NAME)
	{
		DEBUG ("\nptr is not SSA_NAME");
		return NULL;
	}
	DEBUG ("\nptr is SSA_NAME");

	tree casted_inside_type = NULL;
	gimple stmt;
	imm_use_iterator imm_iter;
	DEBUG ("\nTraversing ssa uses");
	FOR_EACH_IMM_USE_STMT (stmt, imm_iter, ptr)
	{
		if (!is_gimple_assign (stmt))
			continue;
#if DEBUG_CONTAINER
		DEBUG ("\nIterate: ");
		print_gimple_stmt (dump_file, stmt, 0, 0);
#endif

		// use_operand_p use_p;
		// FOR_EACH_IMM_USE_ON_STMT (use_p, imm_iter)
		// {
		//  tree use = USE_FROM_PTR (use_p);
		//  RESULT ("\nuse ssa\n");
		//  print_node (dump_file, 0, use, 0);
		// }

		tree lhsop = gimple_assign_lhs (stmt);
		tree rhsop = (gimple_num_ops (stmt) == 2) ? gimple_assign_rhs1 (stmt) : NULL;

		if (rhsop == ptr)
			if (casted_inside_type = get_casted_inside_type (lhsop))
				BREAK_FROM_IMM_USE_STMT (imm_iter);

		// The typecasted value could be retrieved from LHS/RHS also if
		// PTR is used as MEM[(struct node *)ptr] in LHS/RHS.

		// Note that cs_get_constraint_for() is not helpful in deriving
		// type since it stores void* type of variable used inside MEM.

		// DEBUG ("\nget_memref_casted_inside_type (lhs)");
		// print_node (dump_file, 0, lhsop, 0);
		if (casted_inside_type = get_memref_casted_inside_type (lhsop, ptr))
		{
			DEBUG ("\nComputed type from memref lhs");
			BREAK_FROM_IMM_USE_STMT (imm_iter);
		}

		// DEBUG ("\nget_memref_casted_inside_type (rhs)");
		// print_node (dump_file, 0, rhsop, 0);
		if (casted_inside_type = get_memref_casted_inside_type (rhsop, ptr))
		{
			DEBUG ("\nComputed type from memref rhs");
			BREAK_FROM_IMM_USE_STMT (imm_iter);
		}
	}
	if (!casted_inside_type)
	{
		DEBUG ("\ncasted type not found");
		return NULL;
	}

	DEBUG ("\ncasted_inside_type found");
	// print_node (dump_file, 0, casted_inside_type, 0);
	return casted_inside_type;
}
//AN
//AN /**
//AN  * This function computes the tree of heap allocated by malloc(). It removes
//AN  * POINTER_TYPE from the LHS.
//AN  */
//AN
tree parser::
get_heap_decl (tree lhs, basic_block bb, struct cgraph_node * cnode)
{
	DEBUG ("\nget_heap_decl()");
	// Get inside of POINTER_TYPE lhs i.e. get the type of the heap
	// location pointed by lhs.
	tree casted_lhs_inside_type = get_casted_inside_type (lhs);

	tree heap_decl;
	if (casted_lhs_inside_type)
	{
		DEBUG ("\nGot casted_lhs_inside_type");
		// Use this if casted_lhs_inside_type contains RECORD_TYPE (e.g.) directly
		heap_decl = build_fake_var_decl (casted_lhs_inside_type);
		// Use this if casted_lhs_inside_type is VAR_DECL containing
		// POINTER_TYPE containing RECORD_TYPE (e.g.)
		//heap_decl = build_fake_var_decl (TREE_TYPE (TREE_TYPE (SSAVAR (casted_lhs_inside_type))));
	}
	// Benchmark bzip2. default_bzalloc() returns heap with 'void *'. Its
	// type cannot be derived. This is not an error.
	else
	{
		// Do not print bb and cnode. They might be null.
//      RESULT ("\nError:? Cannot compute typecasted value of heap");
		// Prashant: C type 'void *' is ptr_type_node
		heap_decl = build_fake_var_decl (ptr_type_node);
		// A heap location is not of POINTER_TYPE. Create VOID_TYPE.
		// But this gives some problem with cs_first_vi_for_offset().
		// heap_decl = build_fake_var_decl (void_type_node);
		DECL_EXTERNAL (heap_decl) = 1;
		return heap_decl;
	}

	return heap_decl;
}
//AN
//AN /* Create a new heap variable with NAME. Return the created variable.  */
//AN
csvarinfo_t parser::
cs_make_heapvar_for (tree lhs, const char *name, basic_block bb, struct cgraph_node * cnode)
{
	/* Append 'heap' with the its index in csvarinfo. */
	char *tempname;
	asprintf (&tempname, "%s.%d", name, csvarmap.size()); //VEC_size (csvarinfo_t, csvarmap)
	const char * heap_name = ggc_strdup (tempname);

	// Get heap type from lhs
	tree heap_decl = get_heap_decl (lhs, bb, cnode);
	if (!heap_decl)
	{
		RESULT ("\nError: heap_decl not created");
		return NULL;
	}

	unsigned int heap_id = cs_create_variable_info_for (heap_decl, heap_name, bb, cnode);
	csvarinfo_t heap_var = variable_data[heap_id]; // VEC_index (csvarinfo_t, variable_data, heap_id);
	for (csvarinfo_t temp = heap_var; temp; temp = temp->next)
	{
		temp->is_heap_var = true;
		temp->scoping_function = NULL;
	}

	DEBUG ("\n%s(%d) TYPE:\n", heap_var->name, heap_var->id);
	// print_node (dump_file, 0, heap_decl, 0);

	return heap_var;
}
//AN
//AN /**
//AN  * Create offsets of heap variables with HEAP_NAME. This function is called
//AN  * on-the-fly with the analysis i.e. when ORIGINAL_HEAP is already in existence
//AN  * but its OFFSET does not exist. Since ORIGINAL_HEAP is already in existence
//AN  * in VARIABLE_DATA at offset 0, replace newly created offset 0 with
//AN  * ORIGINAL_HEAP in the chain of offsets.
//AN  */
//AN
//AN csvarinfo_t parser::
//AN cs_make_heapvar_offset_for (csvarinfo_t original_heap,
//AN    tree heap_pointer_type,
//AN    unsigned int offset,
//AN    const char * heap_name,
//AN    basic_block bb,
//AN    struct cgraph_node * cnode)
//AN {
//AN    // Benchmark bzip2. default_bzalloc() returns heap with 'void *'. Its
//AN    // type cannot be derived. This is not an error.
//AN    RESULT ("\non-the-fly creation of heap nodes.");
//AN
//AN    // Create all offsets of type HEAP_POINTER_TYPE
//AN    tree heap_decl = get_heap_decl (heap_pointer_type, bb, cnode);
//AN    if (!heap_decl)
//AN    {
//AN        RESULT ("\nError: heap_decl not created");
//AN        return NULL;
//AN    }
//AN #if DEBUG_CONTAINER
//AN    else
//AN    {
//AN        DEBUG ("\nget_heap_decl(): ");
//AN        print_node (dump_file, 0, heap_decl, 0);
//AN    }
//AN #endif
//AN
//AN    unsigned int heap_id = cs_create_variable_info_for (heap_decl, heap_name, bb, cnode);
//AN    csvarinfo_t heap_var = VEC_index (csvarinfo_t, variable_data, heap_id);
//AN    for (csvarinfo_t temp = heap_var; temp; temp = temp->next)
//AN    {
//AN        DEBUG ("\nIterate heap %s(%d)=offset=%d",
//AN            temp->name, temp->id, temp->offset);
//AN        temp->is_heap_var = true;
//AN        temp->scoping_function = NULL;
//AN    }
//AN
//AN    // Replace HEAP_VAR.0 (0 offset) with ORIGINAL_HEAP
//AN    original_heap->next = heap_var->next;
//AN    original_heap->decl = heap_var->decl;
//AN    original_heap->is_unknown_size_var = heap_var->is_unknown_size_var;
//AN    original_heap->fullsize = heap_var->fullsize;
//AN    original_heap->size = heap_var->size;
//AN    original_heap->is_full_var = heap_var->is_full_var;
//AN
//AN    heap_var->next = NULL;
//AN    heap_var->decl = NULL;
//AN
//AN    void **slot = pointer_map_contains (vi_for_tree, original_heap->decl);
//AN    if (!slot)
//AN    {
//AN        RESULT ("\nError: New field offset variables should be created only if they did not already exist");
//AN        return NULL;
//AN    }
//AN    *slot = original_heap;
//AN
//AN #if DEBUG_CONTAINER
//AN    csvarinfo_t var = cs_lookup_vi_for_tree (original_heap->decl);
//AN    DEBUG ("\nFound heap %d", var->id);
//AN #endif
//AN
//AN    // The required offset may not be found exactly in the created chain of
//AN    // offsets. It should, however, overlap.
//AN    DEBUG ("\nFind heap %s(%d) offset=%d", original_heap->name, original_heap->id, offset);
//AN    csvarinfo_t heap_offset_var = cs_first_vi_for_offset (original_heap, offset);
//AN    if (heap_offset_var)
//AN        DEBUG ("\nReturning heap %s(%d)=offset=%d",
//AN            heap_offset_var->name, heap_offset_var->id, heap_offset_var->offset);
//AN    else
//AN        DEBUG ("\nHeap %s(%d) offset=%d not found",
//AN            original_heap->name, original_heap->id, offset);
//AN
//AN    return heap_offset_var;
//AN }
//AN
//AN #if 0
//AN /* Create a new artificial heap variable with NAME.
//AN    Return the created variable.  */
//AN
//AN csvarinfo_t parser::
//AN cs_make_heapvar_for (csvarinfo_t lhs, const char *name, basic_block bb, struct cgraph_node * cnode)
//AN {
//AN   csvarinfo_t vi;
//AN   tree heapvar;
//AN   const char *newname = "NULL";
//AN   char *tempname;
//AN
//AN   // C type 'void *' is ptr_type_node
//AN   heapvar = build_fake_var_decl (ptr_type_node);
//AN   DECL_EXTERNAL (heapvar) = 1;
//AN
//AN   /* Append 'heap' with the its index in csvarinfo. */
//AN   asprintf (&tempname, "%s.%d", name, VEC_size (csvarinfo_t, csvarmap));
//AN   newname = ggc_strdup (tempname);
//AN
//AN   vi = cs_new_var_info (heapvar, newname, cnode);
//AN   //vi->is_artificial_var = true;
//AN   vi->is_heap_var = true;
//AN   vi->is_unknown_size_var = true;
//AN   vi->offset = 0;
//AN   vi->fullsize = ~0;
//AN   vi->size = ~0;
//AN   vi->is_full_var = true;
//AN   cs_insert_vi_for_tree (heapvar, vi);
//AN
//AN   return vi;
//AN }
//AN
//AN // Function created by Vini from cs_make_heapvar_for()
//AN /* Create a new artificial heap variable with NAME.
//AN    Return the created variable.  */
//AN // FIXME: Simply create H.F, H.G etc when H is created in parser::variable_data.
//AN
//AN csvarinfo_t parser::
//AN cs_make_heapvar_offset_for (csvarinfo_t original_heap, tree heap_pointer_type, unsigned int offset, const char *name, basic_block bb, struct cgraph_node * cnode)
//AN {
//AN   csvarinfo_t vi;
//AN   tree heapvar;
//AN   const char *newname = "NULL";
//AN   char *tempname;
//AN
//AN   // Added by Vini. Offsets of same heap node are given the same tree decl.
//AN   // This is required to search this new heapvar from VARIABLE_DATA.
//AN   // FIXME: We should set the next of original_heap to point to this newly
//AN   // created heapvar, so that we do not waste time in searching the whole
//AN   // VARIABLE_DATA.
//AN   // FIELD_CONNECT: This is also important so that H.F.I node is
//AN   // field-connected via NEXT from H=H.F=H.F.G in generate_addressof_nodes ().
//AN   // struct node1 { struct node2 F; }; struct node2 { int * G; int * I; };
//AN
//AN   heapvar = original_heap->decl;
//AN   // Commented out by Vini
//AN   // heapvar = build_fake_var_decl (ptr_type_node);
//AN   DECL_EXTERNAL (heapvar) = 1;
//AN
//AN   /* Append 'heap' with the its index in csvarinfo. */
//AN   // Added by Vini
//AN   asprintf (&tempname, "%s.%u", name, offset);
//AN   // Commented by Vini
//AN   // asprintf (&tempname, "%s.%d", name, VEC_size (csvarinfo_t, csvarmap));
//AN   newname = ggc_strdup (tempname);
//AN
//AN   vi = cs_new_var_info (heapvar, newname, cnode);
//AN   //vi->is_artificial_var = true;
//AN   vi->is_heap_var = true;
//AN   vi->is_unknown_size_var = true;
//AN   vi->offset = offset;         // Set by Vini
//AN   vi->fullsize = ~0;
//AN   vi->size = ~0;
//AN   vi->is_full_var = true;
//AN   // Commented out by Vini. This line does not allow two variables to have the
//AN   // same tree decl.
//AN   // cs_insert_vi_for_tree (heapvar, vi);
//AN
//AN   return vi;
//AN }
//AN #endif
//AN
//AN /**
//AN  * This function returns all the variables with decl equal DECL.
//AN  */
//AN
//AN void parser::
//AN get_field_var_ids (tree decl, set<unsigned int> & field_ids)
//AN {
//AN    if (!decl)
//AN        return;
//AN    DEBUG ("\nget_field_var_ids (tree,...)");
//AN
//AN    csvarinfo_t var_info = cs_lookup_vi_for_tree (decl);
//AN    if (!var_info)
//AN        return;
//AN    // Return if variable does not have any fields
//AN    if (!var_info->offset && !var_info->next)
//AN        return;
//AN    unsigned int var_id = var_info->id;
//AN
//AN    // Return if variable is function. (NEXT field of function csvarinfo_t
//AN    // is connected to its function parameter).
//AN    if (function_var (var_info) || !is_proper_var (var_id))
//AN        return;
//AN
//AN    DEBUG ("\nVar connected to %s(%d): ", var_info->name, var_info->id);
//AN    for (csvarinfo_t temp = var_info; temp; temp = temp->next)
//AN    {
//AN        DEBUG ("%s(%d),", temp->name, temp->id);
//AN        field_ids.insert (temp->id);
//AN    }
//AN }
//AN
//AN /**
//AN  * This function fetches the DECL of VAR_ID (from its csvarinfo_t which may
//AN  * have non-zero offset) and then calls GET_FIELD_VAR_IDS(TREE, ...) which then
//AN  * finds back the csvarinfo_t of offset=0.
//AN  */
//AN
//AN void parser::
//AN get_field_var_ids (unsigned int var_id, set<unsigned int> & field_ids)
//AN {
//AN    csvarinfo_t var_info = VEC_index (csvarinfo_t, variable_data, var_id);
//AN
//AN    // Return if variable is function. (NEXT field of function csvarinfo_t
//AN    // is connected to its function parameter).
//AN    if (function_var (var_info) || !is_proper_var (var_id))
//AN        return;
//AN
//AN    DEBUG ("\nvar_id=%s(%d==%d)", var_info->name, var_info->id, var_id);
//AN
//AN    // All y.0, y.32, y.64 have the same decl. If var_info is for y.32, we
//AN    // want to find all y.0, y.32, y.64. Therefore, pass the decl.
//AN    get_field_var_ids (var_info->decl, field_ids);
//AN }
//AN
//AN void parser::
//AN get_field_var_ids (set<unsigned int> & var_ids, set<unsigned int> & field_ids)
//AN {
//AN    set<unsigned int>::iterator vi;
//AN    for (vi = var_ids.begin (); vi != var_ids.end (); vi++)
//AN        get_field_var_ids (*vi, field_ids);
//AN }
//AN
//AN /**
//AN  * If VAR_ID is y.32, then return y.64. If next field does not exist, it
//AN  * returns VAR_ID. This function is applicable to stack and heap nodes only. In
//AN  * case of globals, VAR_ID is returned.
//AN  */
//AN
//AN unsigned int parser::
//AN get_next_field (unsigned int var_id)
//AN {
//AN    csvarinfo_t var_info = VEC_index (csvarinfo_t, variable_data, var_id);
//AN    if (!var_info)
//AN        return var_id;
//AN
//AN    if (var_info->is_global_var || !is_proper_var (var_id))
//AN        return var_id;
//AN    DEBUG ("\nvar_id=%s(%d==%d)",
//AN        var_info->name, var_info->id, var_id);
//AN
//AN    csvarinfo_t next_field = var_info->next;
//AN    if (next_field)
//AN    {
//AN        DEBUG ("\nnext_field=%s(%d)",
//AN            next_field->name, next_field->id);
//AN        return next_field->id;
//AN    }
//AN    DEBUG ("\nnext_field not found");
//AN    return var_id;
//AN }
//AN
//AN // Added by Vini
void parser::
get_offset_sequence (tree ref, list<unsigned int> & offset_sequence)
{
	// This ref is of the type x->f and not x.f if x is COMPONENT_REF.
	if (TREE_CODE (ref) == COMPONENT_REF)
	{
		// RESULT ("\n");
		// print_node (dump_file, 0, ref, 0);
		tree subtree = TREE_OPERAND (ref, 0);
		tree offset = TREE_OPERAND (ref, 1);

		if (TREE_CODE (offset) == FIELD_DECL)
		{
			DEBUG ("\nbit-pos=%lld\n", int_bit_position (offset));
			// print_node_brief (dump_file, 0, offset, 0);
			get_offset_sequence (subtree, offset_sequence);
			offset_sequence.push_back (int_bit_position (offset));
		}
	}
}
//AN
void parser::
copy_offset_sequence (list<unsigned int> ** dest, list<unsigned int> & src)
{
	DEBUG ("\ncopy_offset_sequence");
	*dest = new list<unsigned int>;
	DEBUG ("\nAllocate offset_sequence %x", *dest);
	(**dest) = src;
}
//AN
void parser::
append_offset_sequence (list<unsigned int> ** dest, list<unsigned int> & src)
{
	if (!*dest)
	{
		copy_offset_sequence (dest, src);
		return;
	}
	DEBUG ("\nappend_offset_sequence");
	list<unsigned int>::iterator si;
	for (si = src.begin (); si != src.end (); si++)
		(**dest).push_back (*si);
}
//AN
void parser::
print_offset_sequence (list<unsigned int> * offset_sequence)
{
	DEBUG ("\nOffset-sequence (addr=%x): ", offset_sequence);
	list<unsigned int>::iterator si;
	for (si = (*offset_sequence).begin (); si != (*offset_sequence).end (); si++)
		DEBUG ("%lld,", *si);
}
//AN
//AN /* Create a constraint ID = &FROM. */
void parser::
cs_make_constraint_from (csvarinfo_t vi, int from, basic_block bb)
{
	struct constraint_expr lhs, rhs;

	lhs.var = vi->id;
	lhs.offset = 0;
	lhs.type = SCALAR;

	rhs.var = from;
	rhs.offset = 0;
	rhs.type = ADDRESSOF;
	cs_process_constraint (new_constraint (lhs, rhs), bb);
}
//AN
//AN /* Create a new artificial heap variable with NAME and make a
//AN    constraint from it to LHS.  Return the created variable.  */
csvarinfo_t parser::
cs_make_constraint_from_heapvar (tree lhs, const char *name, basic_block bb, struct cgraph_node * cnode)
{
	csvarinfo_t vi = cs_make_heapvar_for (lhs, name, bb, cnode);
	csvarinfo_t lhs_var = cs_get_vi_for_tree (lhs, bb, cnode);
	cs_make_constraint_from (lhs_var, vi->id, bb);

	return vi;
}
//AN
//AN /* Find the first varinfo in the same variable as START that overlaps with
//AN    OFFSET.  If there is no such varinfo the varinfo directly preceding
//AN    OFFSET is returned.  */
csvarinfo_t parser::        /* Look into */
cs_first_or_preceding_vi_for_offset (csvarinfo_t start,
                                     unsigned HOST_WIDE_INT offset)
{
	/* If we cannot reach offset from start, lookup the first field
	   and start from there.  */
	if (start->offset > offset)
		start = cs_lookup_vi_for_tree (start->decl);

	/* We may not find a variable in the field list with the actual
	   offset when when we have glommed a structure to a variable.
	   In that case, however, offset should still be within the size
	   of the variable.
	   If we got beyond the offset we look for return the field
	   directly preceding offset which may be the back field.  */
	while (start->next && offset >= start->offset
	        && !((offset - start->offset) < start->size))
		start = start->next;

	return start;
}
//AN
//AN /* Dereference the constraint expression CONS, and return the result.
//AN    DEREF (ADDRESSOF) = SCALAR
//AN    DEREF (SCALAR) = DEREF
//AN    DEREF (DEREF) = (temp = DEREF1; result = DEREF(temp))
//AN    This is needed so that we can handle dereferencing DEREF constraints.  */
void parser::
cs_do_deref (vector<ce_s> *constraints, basic_block bb, struct cgraph_node * cnode)
{
	DEBUG ("\ncs_do_deref()");
	struct constraint_expr *c;
	unsigned int i = 0;

	//AH FOR_EACH_VEC_ELT (ce_s, *constraints, i, c) {
	FOR_EACH_VEC_ELT (*constraints, i, c) {
		if (c->type == SCALAR)
		{
			DEBUG ("\nSCALAR -> DEREF");
			c->type = DEREF;
		}
		else if (c->type == ADDRESSOF)
		{
			DEBUG ("\nADDRESSOF -> SCALAR");
			c->type = SCALAR;
		}
		else if (c->type == DEREF)
		{
			DEBUG ("\nDEREF");
			struct constraint_expr tmplhs;
			tmplhs = cs_new_scalar_tmp_constraint_exp ("dereftmp", cnode);
			cs_process_constraint (new_constraint (tmplhs, *c), bb);
			c->var = tmplhs.var;
		}
		else
			gcc_unreachable ();
	}
}
//AN
//AN /* Get constraint expressions for offsetting PTR by OFFSET.  Stores the
//AN    resulting constraint expressions in *RESULTS.  */
void parser::
cs_get_constraint_for_ptr_offset (tree ptr, tree offset,
                                  vector<ce_s> *results, basic_block bb, struct cgraph_node * cnode)
{
	DEBUG ("\ncs_get_constraint_for_ptr_offset()");
	struct constraint_expr c;
	unsigned int j, n;
	HOST_WIDE_INT rhsunitoffset, rhsoffset;

	//AH if (offset == NULL_TREE || !host_integerp (offset, 0))
	if (offset == NULL_TREE || !tree_fits_uhwi_p (offset))
	{
		rhsoffset = UNKNOWN_OFFSET;
		DEBUG ("\nUNKNOWN_OFFSET used in cs_get_constraint_for_ptr_offset() --1");
	}
	else {
		DEBUG ("\nin else of cs_get_constraint_for_ptr_offset()");
		/* Make sure the bit-offset also fits.  */
		rhsunitoffset = TREE_INT_CST_LOW (offset);
		rhsoffset = rhsunitoffset * BITS_PER_UNIT;
		if (rhsunitoffset != rhsoffset / BITS_PER_UNIT)
		{
			rhsoffset = UNKNOWN_OFFSET;
			DEBUG ("\nUNKNOWN_OFFSET used in cs_get_constraint_for_ptr_offset() --1");
		}
		DEBUG ("\noffset %llu, rhsoffset %llu", offset, rhsoffset);
	}

	cs_get_constraint_for_rhs (ptr, results, bb, cnode);
	if (rhsoffset == 0)
		return;

	/* As we are eventually appending to the solution do not use
	   VEC_iterate here. */
	//AH n = VEC_size (ce_s, *results);
	n = results->size();
	for (j = 0; j < n; j++) {
		csvarinfo_t curr;
		//AH c = *VEC_index (ce_s, *results, j);
		c = (*results)[j];
		curr = cs_get_varinfo (c.var);

		/* If this varinfo represents a full variable just use it. */
		if (c.type == ADDRESSOF && curr->is_full_var)
		{
			c.offset = 0;
		}
		/* If we do not know the offset add all subfields. */
		else if (c.type == ADDRESSOF && rhsoffset == UNKNOWN_OFFSET) {
			csvarinfo_t temp = cs_lookup_vi_for_tree (curr->decl);
			do {
				struct constraint_expr c2;
				c2.var = temp->id;
				c2.type = ADDRESSOF;
				c2.offset = 0;
				if (c2.var != c.var)
				{
					DEBUG ("\npush c2 ");
					DEBUG ("\noffset seq 03 %d", c2.offset_sequence);
					//AH VEC_push_back (ce_s, heap, *results, &c2);
					results->push_back(c2);
				}
				temp = temp->next;
			} while (temp);
		}
		else if (c.type == ADDRESSOF) {
			csvarinfo_t temp;
			unsigned HOST_WIDE_INT offset = curr->offset + rhsoffset;

			/* Search the sub-field which overlaps with the
			   pointed-to offset.  If the result is outside of the variable
			   we have to provide a conservative result, as the variable is
			   still reachable from the resulting pointer (even though it
			   technically cannot point to anything).  The back and first
			   sub-fields are such conservative results.
			   ???  If we always had a sub-field for &object + 1 then
			   we could represent this in a more precise way.  */
			if (rhsoffset < 0 && curr->offset < offset)
				offset = 0;
			temp = cs_first_or_preceding_vi_for_offset (curr, offset);

			/* If the found variable is not exactly at the pointed to
			  result, we have to include the next variable in the
			  solution as well.  Otherwise two increments by offset / 2
			  do not result in the same or a conservative superset
			  solution.  */
			if (temp->offset != offset && temp->next != NULL) {
				struct constraint_expr c2;
				c2.var = temp->next->id;
				c2.type = ADDRESSOF;
				c2.offset = 0;
				DEBUG ("\npush c2");
				DEBUG ("\noffset seq 04 %d", c2.offset_sequence);
				//AH VEC_push_back (ce_s, heap, *results, &c2);
				results->push_back(c2);
			}
			c.var = temp->id;
			c.offset = 0;
		}
		else
		{
			c.offset = rhsoffset;
			// Added by Pritam
			c.pointer_arithmetic = true;
			DEBUG ("\nc.var=%d, ptr_arith=1", c.var);
		}

		//AH VEC_replace (ce_s, *results, j, &c);
		(*results)[j] = c;
	}
}

//AN
//AN /* Given a COMPONENT_REF T, return the constraint_expr vector for it.
//AN    If address_p is true the result will be taken its address of.
//AN    If lhs_p is true then the constraint expression is assumed to be used
//AN    as the lhs.  */
void parser::
cs_get_constraint_for_component_ref (tree t, vector<ce_s> *results,
                                     bool address_p, bool lhs_p, basic_block bb, struct cgraph_node * cnode)
{
	DEBUG ("\ncs_get_constraint_for_component_ref");

	tree orig_t = t;
	HOST_WIDE_INT bitsize = -1;
	HOST_WIDE_INT bitmaxsize = -1;
	HOST_WIDE_INT bitpos;
	tree forzero;
	struct constraint_expr *result;

	/* Some people like to do cute things like take the address of
	  &0->a.b */
	forzero = t;
	while (handled_component_p (forzero)
	        || INDIRECT_REF_P (forzero)
	        || TREE_CODE (forzero) == MEM_REF)
		forzero = TREE_OPERAND (forzero, 0);

	if (CONSTANT_CLASS_P (forzero) && integer_zerop (forzero)) {
		struct constraint_expr temp;
		temp.offset = 0;
		temp.var = readonly_id;
		temp.type = SCALAR;
		DEBUG ("\npush temp");
		DEBUG ("\noffset seq 05 %d", temp.offset_sequence);
		results->push_back (temp); //AH VEC_push_back (ce_s, heap, *results, &temp);
		return;
	}

	/* Handle type-punning through unions. If we are extracting a pointer
	   from a union via a possibly type-punning access that pointer
	   points to anything, similar to a conversion of an integer to
	   a pointer.  */
	if (!lhs_p) {
		tree u;
		for (u = t;
		        TREE_CODE (u) == COMPONENT_REF || TREE_CODE (u) == ARRAY_REF;
		        u = TREE_OPERAND (u, 0))
			if (TREE_CODE (u) == COMPONENT_REF
			        && TREE_CODE (TREE_TYPE (TREE_OPERAND (u, 0))) == UNION_TYPE)
			{
				/*
				    // Commented out by Prashant
				          struct constraint_expr temp;

				          temp.offset = 0;
				          temp.var = anything_id;
				          temp.type = ADDRESSOF;
				          VEC_push_back (ce_s, heap, *results, &temp);
				*/
				return;
			}
	}

	// The offset is lost after calling get_ref_base_and_extent(). We want to
	// recursively traverse the nested offset sequence if t contains dereference
	// through -> i.e. result->type==DEREF. Therefore, we save the tree in
	// ORIG_TREE here and compute the offset-sequence only if
	// result->type==DEREF below.
	tree orig_tree = t;
	t = get_ref_base_and_extent (t, &bitpos, &bitsize, &bitmaxsize);
	DEBUG ("\nvar=%s, bitpos=%lld, bitsize=%lld, bitmaxsize=%lld\n",
	       get_name (t), bitpos, bitsize, bitmaxsize);

	// print_node (dump_file, 0, t, 0);

	/* Pretend to take the address of the base, we'll take care of
	   adding the required subset of sub-fields below.  */
	cs_get_constraint_for_1 (t, results, true, lhs_p, bb, cnode);
	//AH results->size()if (VEC_size (ce_s, *results) == 0)
	if (results->size() == 0)
		return;
	else
		gcc_assert (results->size() == 1); //AH gcc_assert (VEC_size (ce_s, *results) == 1);


	result = &(results->back()); //AH result = VEC_back (ce_s, *results);
#if DEBUG_CONTAINER
	DEBUG ("\nafter cs_get_constraint_for_1()");
	struct constraint_expr *rhsp;
	unsigned j;
	FOR_EACH_VEC_ELT (ce_s, *results, j, rhsp) {
		DEBUG ("\nrhsp %d offset %llu\n", rhsp->var, rhsp->offset);
	}
#endif

	if (result->type == SCALAR
	        && cs_get_varinfo (result->var)->is_full_var)
		/* For single-field vars do not bother about the offset.  */
		result->offset = 0;
	else if (result->type == SCALAR) {
		/* In languages like C, you can access one past the end of an
		array.  You aren't allowed to dereference it, so we can
		ignore this constraint. When we handle pointer subtraction,
		we may have to do something cute here.  */

		if ((unsigned HOST_WIDE_INT)bitpos < cs_get_varinfo (result->var)->fullsize
		        && bitmaxsize != 0) {
			/* It's also not true that the constraint will actually start at the
			   right offset, it may start in some padding.  We only care about
			   setting the constraint to the first actual field it touches, so
			   walk to find it.  */
			struct constraint_expr cexpr = *result;
			csvarinfo_t curr;
			// results->back(); //AH VEC_pop (ce_s, *results);
			results->pop_back();
			cexpr.offset = 0;
			for (curr = cs_get_varinfo (cexpr.var); curr; curr = curr->next) {
				if (ranges_overlap_p (curr->offset, curr->size,
				                      bitpos, bitmaxsize)) {
					cexpr.var = curr->id;
					DEBUG ("\ncexpr.var=%d curr->offset=%lld", cexpr.var);
					DEBUG ("\noffset seq 06 %d", cexpr.offset_sequence);
					results->push_back (cexpr); //AH VEC_push_back (ce_s, heap, *results, &cexpr);
					if (address_p)
						break;
				}
			}
			/* If we are going to take the address of this field then
			   to be able to compute reachability correctly add at least
			   the back field of the variable.  */
			if (address_p && results->size() == 0) {
				curr = cs_get_varinfo (cexpr.var);
				while (curr->next)
					curr = curr->next;
				cexpr.var = curr->id;
				DEBUG ("\npush cexpr");
				DEBUG ("\noffset seq 07 %d", cexpr.offset_sequence);
				results->push_back(cexpr);
#if DEBUG_CONTAINER
				DEBUG ("\naddress_p");
				struct constraint_expr *rhsp;
				unsigned j;
				FOR_EACH_VEC_ELT (*results, j, rhsp) {//AH FOR_EACH_VEC_ELT (ce_s, *results, j, rhsp) {
					DEBUG ("\nrhsp %d offset %llu\n", rhsp->var, rhsp->offset);
				}
#endif
			}
			/*
			      // Commented out by Prashant
			else if (VEC_size (ce_s, *results) == 0)
			       // Assert that we found *some* field there. The user couldn't be
			       // accessing *only* padding.
			       // Still the user could access one past the end of an array
			       // embedded in a struct resulting in accessing *only* padding.
			       // Or accessing only padding via type-punning to a type
			       // that has a filed just in padding space.
			       {
			         cexpr.type = SCALAR;
			         cexpr.var = anything_id;
			         cexpr.offset = 0;
			         VEC_push_back (ce_s, heap, *results, &cexpr);
			       }
			 */
		}
		else if (bitmaxsize == 0) {
			if (dump_file && (dump_flags & TDF_DETAILS))
				DEBUG ("Access to zero-sized part of variable, ignoring\n");
		}
		else if (dump_file && (dump_flags & TDF_DETAILS))
			DEBUG ("Access to past the end of variable, ignoring\n");
	}
	else if (result->type == DEREF) {
		/* If we do not know exactly where the access goes say so.  Note
		that only for non-structure accesses we know that we access
		at most one subfiled of any variable.  */
		// Vini:
		if (bitpos == -1 || bitsize != bitmaxsize || result->offset == UNKNOWN_OFFSET)
		{
			result->offset = UNKNOWN_OFFSET;
			DEBUG ("\nUNKNOWN_OFFSET used in cs_get_constraint_for_component_ref ()");
		}
		/* Look into : Structure variables */
		// Vini: Used when x->f is a record type and NOT a pointer
		else if (AGGREGATE_TYPE_P (TREE_TYPE (orig_t)))
		{
			DEBUG ("\nAGGREGATE_TYPE_P (orig_t)");
			result->offset = bitpos;
			list<unsigned int> offset_sequence;
			get_offset_sequence (orig_tree, offset_sequence);
			copy_offset_sequence (&result->offset_sequence, offset_sequence);
			print_offset_sequence (result->offset_sequence);
			DEBUG ("\nresult->offset=bitpos=%lld", bitpos);
		}
		else
		{
			DEBUG ("\n!!! AGGREGATE_TYPE_P (orig_t)");
			if (result->offset)
				DEBUG ("\nError:? hmmm interesting");
			result->offset += bitpos;
			list<unsigned int> offset_sequence;
			get_offset_sequence (orig_tree, offset_sequence);
			append_offset_sequence (&result->offset_sequence, offset_sequence);
			print_offset_sequence (result->offset_sequence);
			DEBUG ("\nresult->offset=%lld,bitpos=%lld", result->offset, bitpos);
		}
	}
	else
		gcc_unreachable ();
}
//AN
//AN /* Get a constraint expression vector from an SSA_VAR_P node.
//AN    If address_p is true, the result will be taken its address of.  */
void parser::
cs_get_constraint_for_ssa_var (tree t, vector<ce_s> *results, bool address_p, basic_block bb, struct cgraph_node * cnode)
{
	DEBUG ("\ncs_get_constraint_for_ssa_var");
	struct constraint_expr cexpr;
	csvarinfo_t vi;
	CERR (AN: cs_get_constraint_for_ssa_var 1 % % % % % % % % % % );

	/* We allow FUNCTION_DECLs here even though it doesn't make much sense. */
	gcc_assert (SSA_VAR_P (t) || DECL_P (t));

	DEBUG ("\ngcc_assert() saved");

	CERR (AN: cs_get_constraint_for_ssa_var 2 % % % % % % % % % % );

	/* For parameters, get at the points-to set for the actual parm decl. */
	if (TREE_CODE (t) == SSA_NAME
	        && SSA_NAME_IS_DEFAULT_DEF (t)
	        && (TREE_CODE (SSA_NAME_VAR (t)) == PARM_DECL
	            || TREE_CODE (SSA_NAME_VAR (t)) == RESULT_DECL))
	{
		CERR (AN: cs_get_constraint_for_ssa_var 3 % % % % % % % % % % );
		DEBUG ("\nssa again");
		cs_get_constraint_for_ssa_var (SSA_NAME_VAR (t), results, address_p, bb, cnode);

		return;
	}

	CERR (AN: cs_get_constraint_for_ssa_var 4 % % % % % % % % % % );
	vi = cs_get_vi_for_tree (t, bb, cnode);
	cexpr.var = vi->id;
	DEBUG ("\nIn cs_get_constraint_for ssa_var: vi %s, id %d, offset %llu\n",
	       vi->name, vi->id, vi->offset);
	DEBUG ("\nIndex of variable %d", vi->id);

	CERR (AN: cs_get_constraint_for_ssa_var 5 % % % % % % % % % % );

	cexpr.type = SCALAR;
	cexpr.offset = 0;

	/* If we are not taking the address of the constraint expr, add all
	   sub-fiels of the variable as well.  */
	if (!address_p)
		DEBUG ("\n!address_p");
	if (!vi->is_full_var)
		DEBUG ("\n!vi->is_full_var");
	else
		DEBUG ("\nvi->is_full_var");

	if (!address_p && !vi->is_full_var) {
		for (; vi; vi = vi->next) {
			cexpr.var = vi->id;

			DEBUG ("\nIndex of variable in loop %d", vi->id);
			results->push_back (cexpr); //AH VEC_push_back (ce_s, heap, *results, &cexpr);
		}
		DEBUG ("\nEnd of loop");
		return;
	}
	results->push_back (cexpr); //AH VEC_push_back (ce_s, heap, *results, &cexpr);

}
//AN
//AN /* Given a tree T, return the constraint expression for it.  */
void parser::
cs_get_constraint_for_1 (tree t, vector<ce_s> *results, bool address_p,
                         bool lhs_p, basic_block bb, struct cgraph_node * cnode)
{
	DEBUG ("\ncs_get_constraint_for_1");
	struct constraint_expr temp;

	/* x = integer is all glommed to a single variable, which doesn't
	  point to anything by itself.  That is, of course, unless it is an
	  integer constant being treated as a pointer, in which case, we
	  will return that this is really the addressof anything.  This
	  happens below, since it will fall into the default case. The only
	  case we know something about an integer treated like a pointer is
	  when it is the NULL pointer, and then we just say it points to
	  NULL.

	  Do not do that if -fno-delete-null-pointer-checks though, because
	  in that case *NULL does not fail, so it _should_ alias *anything.
	  It is not worth adding a new option or renaming the existing one,
	  since this case is relatively obscure.  */
	if ((TREE_CODE (t) == INTEGER_CST && integer_zerop (t))
	        /* The only valid CONSTRUCTORs in gimple with pointer typed
	        elements are zero-initializer.  But in IPA mode we also
	        process global initializers, so verify at least.  */
	        || (TREE_CODE (t) == CONSTRUCTOR
	            && CONSTRUCTOR_NELTS (t) == 0)) {
		if (flag_delete_null_pointer_checks) {
			temp.var = null_id;
			temp.type = ADDRESSOF;
			temp.offset = 0;
			DEBUG ("\nnull pointer");

			results->push_back(temp);
			DEBUG ("\noffset seq 01 %d", temp.offset_sequence);
		}
		return;
	}

	/* String constants are read-only. Don't consider them.
	 if (TREE_CODE (t) == STRING_CST)
	     return;*/

	/* String constants are read-only. */
	if (TREE_CODE (t) == STRING_CST) {
		temp.var = readonly_id;
		temp.type = SCALAR;
		temp.offset = 0;
		results->push_back(temp); //VEC_push_back (ce_s, heap, *results, &temp);
		DEBUG ("\noffset seq 02 %d", temp.offset_sequence);
		return;
	}
	switch (TREE_CODE_CLASS (TREE_CODE (t))) {
	case tcc_expression:
	{
		switch (TREE_CODE (t)) {
		case ADDR_EXPR:
			DEBUG ("\nADDR_EXPR");
			cs_get_constraint_for_address_of (TREE_OPERAND (t, 0), results, bb, cnode);
			DEBUG ("\noffset seq 1 %d", results->back().offset_sequence);
			return;
		default:;
		}
		break;
	}
	case tcc_reference:
	{
		switch (TREE_CODE (t)) {
		case MEM_REF:
		{
			DEBUG ("\nMEM_REF");
			struct constraint_expr cs;
			csvarinfo_t vi, curr;
			tree off = wide_int_to_tree (sizetype, mem_ref_offset (t)); //AH tree off = double_int_to_tree (sizetype, mem_ref_offset (t));
			cs_get_constraint_for_ptr_offset (TREE_OPERAND (t, 0), off, results, bb, cnode);
			if (results->size() == 0)
				return;
			cs_do_deref (results, bb, cnode);
			DEBUG ("\noffset seq 2 %d", results->back().offset_sequence);
			/* If we are not taking the address then make sure to process
			all subvariables we might access.  */
			cs = (results->back());
			DEBUG ("\ncs.var=%d, cs.ptr_arith=%d", cs.var, cs.pointer_arithmetic);
			if (address_p || cs.type != SCALAR)
				return;

			vi = cs_get_varinfo (cs.var);
			curr = vi->next;
			if (!vi->is_full_var && curr) {
				unsigned HOST_WIDE_INT size;

				if (tree_fits_uhwi_p (TYPE_SIZE (TREE_TYPE (t))))
					size = TREE_INT_CST_LOW (TYPE_SIZE (TREE_TYPE (t)));
				else
					size = -1;
				for (; curr; curr = curr->next) {
					if (curr->offset - vi->offset < size) {
						cs.var = curr->id;
						results->push_back(cs); //VEC_push_back (ce_s, heap, *results, &cs);
						DEBUG ("\noffset seq 03 %d", cs.offset_sequence);
					}
					else
						break;
				}
			}
			return;
		}
		case ARRAY_REF:
		case ARRAY_RANGE_REF:
		case COMPONENT_REF:
			DEBUG ("\nARRAY_REF|ARRAY_RANGE_REF|COMPONENT_REF");
			cs_get_constraint_for_component_ref (t, results, address_p, lhs_p, bb, cnode);
			DEBUG ("\noffset seq 3 %d", results->back().offset_sequence);
#if DEBUG_CONTAINER
			DEBUG ("\nafter ARRAY_REF|ARRAY_RANGE_REF|COMPONENT_REF");
			struct constraint_expr *rhsp;
			unsigned j;
			FOR_EACH_VEC_ELT (*results, j, rhsp) {
				DEBUG ("\nrhsp %d offset %llu\n", rhsp->var, rhsp->offset);
			}
#endif

			return;
		case VIEW_CONVERT_EXPR:
			DEBUG ("\nVIEW_CONVERT_EXPR");
			cs_get_constraint_for_1 (TREE_OPERAND (t, 0), results, address_p, lhs_p, bb, cnode);
			DEBUG ("\noffset seq 4 %d", results->back().offset_sequence);
			return;
		/* We are missing handling for TARGET_MEM_REF here.  */
		default:;
		}
		break;
	}
	case tcc_exceptional:
	{
		switch (TREE_CODE (t)) {
		case SSA_NAME:
		{
			DEBUG ("\nSSA_NAME");
			cs_get_constraint_for_ssa_var (t, results, address_p, bb, cnode);
			DEBUG ("\noffset seq 5 %d", results->back().offset_sequence);
			return;
		}
		case CONSTRUCTOR:
		{
			DEBUG ("\nCONSTRUCTOR");
			unsigned int i;
			tree val;
			vector<ce_s> tmp;
			FOR_EACH_CONSTRUCTOR_VALUE (CONSTRUCTOR_ELTS (t), i, val) {
				struct constraint_expr *rhsp;
				unsigned j;
				cs_get_constraint_for_1 (val, &tmp, address_p, lhs_p, bb, cnode);
				// FOR_EACH_VEC_ELT (ce_s, tmp, j, rhsp)
				//     VEC_push_back (ce_s, heap, *results, rhsp);
				// VEC_truncate (ce_s, tmp, 0);
				FOR_EACH_VEC_ELT (tmp, j, rhsp)
				results->push_back (*rhsp);
				DEBUG ("\noffset seq 01 %d", *rhsp->offset_sequence);
				// tmp.truncate (0);
				tmp.clear();
			} DEBUG ("\noffset seq 6 %d", results->back().offset_sequence);
			// VEC_free (ce_s, heap, tmp);
			tmp.clear();
			/* We do not know whether the constructor was complete,
			   so technically we have to add &NOTHinG or &ANYTHinG
			like we do for an empty constructor as well.  */
			return;
		}
		default:;
		}
		break;
	}
	case tcc_declaration:
	{
		DEBUG ("\ntcc_declaration");
		cs_get_constraint_for_ssa_var (t, results, address_p, bb, cnode);
		DEBUG ("\noffset seq 7 %d", results->back().offset_sequence);
		return;
	}
	case tcc_constant:
		DEBUG ("\ntcc_constant");
		return;
	default:;
	}
}
//AN
//AN
//AN
//AN /* Efficiently generates constraints from all entries in *RHSC to all
//AN    entries in *LHSC.  */
void parser::
//cs_process_all_all_constraints (VEC (ce_s, heap) *lhsc, VEC (ce_s, heap) *rhsc, basic_block bb)
cs_process_all_all_constraints (vector<ce_s> lhsc, vector<ce_s> rhsc, basic_block bb)
{
	struct constraint_expr *lhsp, *rhsp;
	unsigned i, j;

#if DEBUG_CONTAINER
	DEBUG ("\nBefore: ");
	print_assignment_data ();
#endif

	FOR_EACH_VEC_ELT1 (ce_s, lhsc, i, lhsp) {
		FOR_EACH_VEC_ELT1 (ce_s, rhsc, j, rhsp) {
			DEBUG ("\ncs_process_all_all_constraints loop");
			DEBUG ("\nlhsp %d offset %llu, rhsp %d offset %llu\n",
			       lhsp->var, lhsp->offset, rhsp->var, rhsp->offset);
//     print_variable_data (lhsp->var);
//     DEBUG ("\n");
//     print_variable_data (rhsp->var);
			cs_process_constraint (new_constraint (*lhsp, *rhsp), bb);
			multi_rhs = true;
		}
		multi_rhs = false;
	}
#if DEBUG_CONTAINER
	DEBUG ("\nAfter: ");
	print_assignment_data ();
#endif
}
//AN
//AN /* Given a tree T, return the constraint expression for taking the
//AN    address of it. */
void parser::
cs_get_constraint_for_address_of (tree t, vector<ce_s> *results, basic_block bb, struct cgraph_node * cnode)
{
	struct constraint_expr *c;
	unsigned int i;
	DEBUG ("\ncs_get_constraint_for_address_of");

	cs_get_constraint_for_1 (t, results, true, true, bb, cnode);
	//AH FOR_EACH_VEC_ELT (ce_s, *results, i, c) {
	FOR_EACH_VEC_ELT (*results, i, c) {
		if (c->type == DEREF)
			c->type = SCALAR;
		else
			c->type = ADDRESSOF;
	}
}
//AN
//AN /* Given a gimple tree T, return the constraint expression vector for it.  */
void parser::
// cs_get_constraint_for (tree t, VEC (ce_s, heap) **results, basic_block bb, struct cgraph_node * cnode)
cs_get_constraint_for (tree t, vector<ce_s> *results, basic_block bb, struct cgraph_node * cnode)
{
	CERR (cs_get_constraint_for 1 % % % % % % % % % % % % );
	// VEC_size (ce_s, *results); //AN
	CERR (cs_get_constraint_for 2 % % % % % % % % % % % % );
	gcc_assert (results->size() == 0);
	// gcc_assert (VEC_size (ce_s, *results) == 0);
	CERR (cs_get_constraint_for 3 % % % % % % % % % % % % );
	DEBUG ("\ncs_get_constraint_for\n");
	cs_get_constraint_for_1 (t, results, false, true, bb, cnode);
	// cs_get_constraint_for_1 (t, *results, false, true, bb, cnode);
}
//AN
//AN /* Creation function node for DECL, using NAME, and return the index
//AN    of the variable we've created for the function.  */
csvarinfo_t parser::
cs_create_func_info_for (tree decl, const char *name, struct cgraph_node * cnode)
{
	csvarinfo_t vi, prev_vi;
	tree arg;
	unsigned int i;
	bool is_varargs = false;
	unsigned int num_args = count_num_arguments (decl, &is_varargs);
	DEBUG ("\nin  cs create func info for : %d", num_args);
	/* Create the variable info.  */
	vi = cs_new_var_info (decl, name, cnode);
	vi->offset = 0;
	vi->size = 1;
	vi->fullsize = num_args + 1;
	vi->may_have_pointers = false;
	if (is_varargs)
		vi->fullsize = ~0;
	cs_insert_vi_for_tree (vi->decl, vi);

	prev_vi = vi;

	/* Set up variables for each argument.  */
	arg = DECL_ARGUMENTS (decl);
	for (i = 1; i < num_args + 1; i++) {
		csvarinfo_t argvi;
		tree argdecl = decl;

		if (arg)
			argdecl = arg;

		argvi = cs_new_var_info (argdecl, alias_get_name (argdecl), cnode);
		argvi->offset = i;
		argvi->size = 1;
		argvi->is_full_var = true;
		argvi->fullsize = vi->fullsize;
		if (arg)
			argvi->may_have_pointers = true; //DEBUG ("\nmay have pointers is true");
		// Avantika puts all the below in the above IF condition, Prashant does not
		gcc_assert (prev_vi->offset < argvi->offset);
		prev_vi->next = argvi;
		prev_vi = argvi;
		if (arg) {
			cs_insert_vi_for_tree (arg, argvi);
			arg = DECL_CHAIN (arg);
		}
	}
	/* Add one representative for all further args.  */
	if (is_varargs) {
		csvarinfo_t argvi;
		const char *newname;
		char *tempname;
		tree decl;

		asprintf (&tempname, "%s.varargs", name);
		newname = ggc_strdup (tempname);
		free (tempname);

		/* Sudakshina: CHANGE DUE TO GCC-4.7.2 */
		/* We need sth that can be pointed to for va_start.  */
		decl = build_fake_var_decl (ptr_type_node);

		/* According to gcc-4.6.*
		   decl = create_tmp_var_raw (ptr_type_node, name);
		   get_var_ann (decl); */

		argvi = cs_new_var_info (decl, newname, cnode);
		argvi->offset = 1 + num_args;
		argvi->size = ~0;
		argvi->is_full_var = true;
		argvi->is_heap_var = true;
		argvi->fullsize = vi->fullsize;
		gcc_assert (prev_vi->offset < argvi->offset);
		prev_vi->next = argvi;
		prev_vi = argvi;
	}

	return vi;
}
//AN
//AN /* Find the first varinfo in the same variable as START that overlaps with
//AN    OFFSET.  Return NULL if we can't find one.  */
//AN /* While creating field offset variables, non-pointer member fields are merged.
//AN  * Therefore, if a member field from the merged fields is accessed, we need to
//AN  * find the merged field with which the accessed field overlaps. For this we
//AN  * can use ranges_overlap_p() or cs_first_vi_for_offset().
//AN  */
csvarinfo_t parser::
cs_first_vi_for_offset (csvarinfo_t start, unsigned HOST_WIDE_INT offset)   /* Look into */
{
	DEBUG ("\ncs_first_vi_for_offset (%s(%d), %lld)", start->name, start->id, offset);

	// Added by Prashant
	offset += start->offset;

	/* If the offset is outside of the variable, bail out.  */
	if (offset >= start->fullsize)
		return NULL;

	// This can never be true because of Prashant's above statement.
	/* If we cannot reach offset from start, lookup the first field
	   and start from there.  */
	if (start->offset > offset)
		start = cs_lookup_vi_for_tree (start->decl);

	while (start) {
		/* We may not find a variable in the field list with the actual
		   offset when when we have glommed a structure to a variable.
		   In that case, however, offset should still be within the size
		   of the variable. */
		if (offset >= start->offset
		        && (offset - start->offset) < start->size)
			return start;

		start = start->next;
	}

	return NULL;
}
//AN
//AN /* Handle aggregate copies by expanding into copies of the respective
//AN    fields of the structures.  */
void parser::
cs_do_structure_copy (tree lhsop, tree rhsop, basic_block bb, struct cgraph_node * cnode)  /* Look into : Structure variables */
{
	struct constraint_expr *lhsp, *rhsp;
	// VEC (ce_s, heap) *lhsc = NULL, *rhsc = NULL;
	vector<ce_s> lhsc, rhsc;
	unsigned j;

	DEBUG ("\ncs_do_structure_copy ()");
	cs_get_constraint_for (lhsop, &lhsc, bb, cnode);
	cs_get_constraint_for_rhs (rhsop, &rhsc, bb, cnode);// cs_get_constraint_for_rhs (rhsop, &rhsc, bb, cnode);

	lhsp = &lhsc[0];// lhsp = VEC_index (ce_s, lhsc, 0);
	rhsp = &rhsc[0];// rhsp = VEC_index (ce_s, rhsc, 0);

	DEBUG ("\nlhs var %d, type %d, offset %ld", lhsp->var, lhsp->type, lhsp->offset);
	DEBUG ("\nrhs var %d, type %d, offset %ld", rhsp->var, rhsp->type, lhsp->offset);

	// Commented by Vini, used by Prashant
//    if (lhsp->type == DEREF)
//       return;
//    if (rhsp->type == DEREF) {
//        gcc_assert (VEC_size (ce_s, rhsc) == 1);
//        rhsp->var = undef_id;
//        rhsp->offset = 0;
//        rhsp->type = ADDRESSOF;
//        cs_process_all_all_constraints (lhsc, rhsc, bb);
//    }

	// Added by Vini
	if (lhsp->type == DEREF || rhsp->type == DEREF)
	{
		if (lhsp->type == DEREF)
		{
			gcc_assert (lhsc.size() == 1);
			// Why added by Vini? Creates duplicate constraint.
			// cs_process_constraint (new_constraint (*lhsp, *rhsp), bb);
			// FIXME: *x=y should produce *x.0+32=y.0+32; *x.32+32=y.32+32
			//lhsp->offset = UNKNOWN_OFFSET;
		}
		if (rhsp->type == DEREF)
		{
			gcc_assert (rhsc.size() == 1);
			// Why added by Vini? Creates duplicate constraint.
			// cs_process_constraint (new_constraint (*lhsp, *rhsp), bb);
			// FIXME: x=*y should produce x.0+32=*y.0+32; x.32+32=*y.32+32
			//rhsp->offset = UNKNOWN_OFFSET;
		}
		cs_process_all_all_constraints (lhsc, rhsc, bb);
	}

	else if (lhsp->type == SCALAR &&
	         (rhsp->type == SCALAR || rhsp->type == ADDRESSOF)) {
		DEBUG ("\nSCALAR = SCALAR");
		HOST_WIDE_INT lhssize, lhsmaxsize, lhsoffset;
		HOST_WIDE_INT rhssize, rhsmaxsize, rhsoffset;
		unsigned k = 0;
		get_ref_base_and_extent (lhsop, &lhsoffset, &lhssize, &lhsmaxsize);
		get_ref_base_and_extent (rhsop, &rhsoffset, &rhssize, &rhsmaxsize);
		DEBUG ("\nVEC_size (ce_s, lhsc) = %d, VEC_size (ce_s, rhsc) = %d", lhsc.size(), rhsc.size());
		// for (j = 0; VEC_iterate (ce_s, lhsc, j, lhsp);) {
		// for (j = 0; lhsc.iterate(j, &lhsp);) {
		for(auto lhsp = lhsc.begin(); lhsp != lhsc.end(); ++lhsp){
			DEBUG ("\nIterate lhs");
			csvarinfo_t lhsv, rhsv;
			rhsp = &rhsc[k];//VEC_index (ce_s, rhsc, k);
			lhsv = cs_get_varinfo (lhsp->var);
			rhsv = cs_get_varinfo (rhsp->var);
			DEBUG ("\nlhsv %s, rhsv %s", lhsv->name, rhsv->name);
			if (lhsv->may_have_pointers
			        && (lhsv->is_full_var
			            || rhsv->is_full_var
			            || ranges_overlap_p (lhsv->offset + rhsoffset, lhsv->size,
			                                 rhsv->offset + lhsoffset, rhsv->size)))
			{
				DEBUG ("\nSomething... 1");
				cs_process_constraint (new_constraint (*lhsp, *rhsp), bb);
			}
			if (!rhsv->is_full_var && (lhsv->is_full_var
			                           || (lhsv->offset + rhsoffset + lhsv->size
			                               > rhsv->offset + lhsoffset + rhsv->size))) {
				DEBUG ("\nSomething... 2");
				++k;
				if (k >= rhsc.size())
					break;
			}
			else
			{
				DEBUG ("\nSomething... 3");
				++j;
			}
		}
	}
	else
	{
		DEBUG ("\nSomething... 4");
		gcc_unreachable ();  // Calls abort ()
	}

	DEBUG ("\nFinish cs_do_structure_copy ()");

	lhsc.clear();
	rhsc.clear();
	// VEC_free (ce_s, heap, lhsc);
	// VEC_free (ce_s, heap, rhsc);
}
//AN
void parser::
cs_init_base_vars (struct cgraph_node * cnode)
{
	// csvarinfo_t var_nothing, var_integer, var_undef;
	csvarinfo_t var_nothing, var_readonly, var_escaped, var_undef, var_universal;

	/* Create an ESCAPED variable, for escaped pointer values. */
	var_escaped = cs_new_var_info (NULL_TREE, "escaped", cnode);
	gcc_assert (var_escaped->id == escaped_id);
	var_escaped->offset = 0;
	var_escaped->size = ~0;
	var_escaped->fullsize = ~0;
	var_escaped->next = NULL;

	/* Create an UNKNOWN variable, for unknown pointer values. */
	var_undef = cs_new_var_info (NULL_TREE, "undef", cnode);
	gcc_assert (var_undef->id == undef_id);
	var_undef->offset = 0;
	var_undef->size = ~0;
	var_undef->fullsize = ~0;
	var_undef->next = NULL;

	/* Create the NULL variable, used to represent that a variable points
	   to NULL.  */
	var_nothing = cs_new_var_info (NULL_TREE, "null", cnode);
	gcc_assert (var_nothing->id == null_id);
	var_nothing->offset = 0;
	var_nothing->size = ~0;
	var_nothing->fullsize = ~0;
	var_nothing->next = NULL;

	/* Create the INTEGER variable, used to represent that a variable points
	   to what an INTEGER "points to".
	   var_integer = cs_new_var_info (NULL_TREE, "integer", cnode);
	   gcc_assert (var_integer->id == integer_id);
	   var_integer->size = ~0;
	   var_integer->fullsize = ~0;
	   var_integer->offset = 0;
	   var_integer->next = NULL;*/

	/* Create the READONLY variable, used to represent string constants
	   and integer pointers. */
	var_readonly = cs_new_var_info (NULL_TREE, "readonly", cnode);
	gcc_assert (var_readonly->id == readonly_id);
	var_readonly->offset = 0;
	var_readonly->size = ~0;
	var_readonly->fullsize = ~0;
	var_readonly->next = NULL;

#if 0
	/* Create the UNIVERSAL variable, used to represent all locations. */
	var_universal = cs_new_var_info (NULL_TREE, "universal", cnode);
	gcc_assert (var_universal->id == universal_id);
	var_universal->size = ~0;
	var_universal->fullsize = ~0;
	var_universal->offset = 0;
	var_universal->next = NULL;
#endif
}
//AN
//AN bool parser::
//AN is_pred_of_end_block (basic_block block)
//AN {
//AN    edge e;
//AN    edge_iterator ei;
//AN    FOR_EACH_EDGE (e, ei, block->succs)
//AN    {
//AN        basic_block succ_block = e->dest;
//AN        unsigned int bt = ((block_information *)(succ_block->aux))->get_block_type ();
//AN        if (bt & END_BLOCK)
//AN            return true;
//AN    }
//AN    return false;
//AN }
//AN
basic_block parser::
get_end_block_of_function (struct cgraph_node *node)
{
	// Added by Vini
	struct function * fun = DECL_STRUCT_FUNCTION (node->decl);
	return fun->cfg->x_exit_block_ptr;

	// Returns the end basic block of the function (The end block, i.e the block
	// before EXIT_BLOCK_PTR).

	// bb_worklist bb_list = worklist_of_cnode (node);
	// int i = n_basic_blocks_for_function (DECL_STRUCT_FUNCTION (node->decl)) - NUM_FIXED_BLOCKS;
	// return bb_list[i].bb;


#if 0
	// Returns the end basic block of the function (The end block, i.e the
	// block before EXIT_BLOCK_PTR).
	// test4i.c has "return" in bb9 (which is END_BLOCK). However the below
	// function returns bb7.
	// return EXIT_BLOCK_PTR_FOR_FUNCTION (DECL_STRUCT_FUNCTION (node->decl))->prev_bb;

	// FIXME: Solution
	// Use block id 1 (i.e. EXIT_BLOCK_PTR_FOR_FUNCTION (...)) as the
	// END_BLOCK. This block (i.e. with id 1) cannot be seen when
	// FOR_EACH_BB is used. But is encountered when ->succs of bb is used.

	// FIXME:
	// This is too inefficient
	struct function * function = DECL_STRUCT_FUNCTION (node->decl);
	basic_block bb;
	FOR_EACH_BB_FN (bb, function)
	{
		if (((block_information *)(bb->aux))->get_block_type () & END_BLOCK)
			return bb;
	}

	// A function may not have any return block if the back statement
	// is exit(...). In this case we choose the previous block of
	// EXIT_BLOCK_PTR  i.e. previous to block id 1.
#if DEBUG_CONTAINER
	const char * function_name = cgraph_node_name (node);
	DEBUG ("\nCannot find end block of function %s", function_name);
#endif
	// FIXME: When there is no return and there are exit() blocks, the
	// following line returns one of the exit() blocks of the function.
	// This way the control flow from other exit() blocks gets missed.
	bb = EXIT_BLOCK_PTR_FOR_FUNCTION (DECL_STRUCT_FUNCTION (node->decl))->prev_bb;
	DEBUG ("\nEnd basic block %d", bb->index);
	return bb;

	// Prashant:
	// bb_worklist bb_list = worklist_of_cnode (node);
	// int i = n_basic_blocks_for_function (DECL_STRUCT_FUNCTION (node->decl)) - NUM_FIXED_BLOCKS;
	// return bb_list[i].bb;
#endif
}

basic_block parser::
get_start_block_of_function (struct cgraph_node *node)
{
	// Added by Vini
	//AN print_node(stderr, 0, node->decl, 0);
	struct function * fun = DECL_STRUCT_FUNCTION (node->decl);
//AN    if (fun == NULL) {
//AN        std::cerr << std::endl << "00000000000000000" << std::endl;
//AN    } else {
//AN        std::cerr << std::endl << "11111111111111111" << std::endl;
//AN    }
	return fun->cfg->x_entry_block_ptr;

	//   return ENTRY_BLOCK_PTR_FOR_FUNCTION (DECL_STRUCT_FUNCTION (node->decl))->next_bb;

#if 0
	//return ENTRY_BLOCK_PTR_FOR_FUNCTION (DECL_STRUCT_FUNCTION (node->decl));

	basic_block start_block = ENTRY_BLOCK_PTR_FOR_FUNCTION (DECL_STRUCT_FUNCTION (node->decl))->next_bb;
	if (!start_block)
		RESULT ("\nError: Cannot find start block");
#endif
}

void parser::
cs_init_alias_vars (struct cgraph_node * cnode)
{
	// VEC (ce_s, heap) *results = NULL;
	// struct constraint_expr csexpr;
	// This gives segmentation fault if constraint_expr contains list<>.
	// VEC_push_back (ms_s, heap, results, &csexpr);
	// csvarmap.create(200);
	// aliases.create(200);
	// csvarmap = VEC_alloc (csvarinfo_t, heap, 200);
	// aliases = VEC_alloc (constraint_t, heap, 200);
	DEBUG ("\ncreate_alloc_pool (constraint)");
	DEBUG ("\ncreate_alloc_pool (csvariable_info)");
	constraint_pool = create_alloc_pool ("Constraint pool", sizeof (struct constraint), 200);
	csvarinfo_pool = create_alloc_pool ("Variable pool", sizeof (struct csvariable_info), 200);
	//KO vi_for_tree = pointer_map_create ();
	vi_for_tree = new hash_map<tree, csvarinfo_t>; //KO NEWADD
	cs_init_base_vars (cnode);
	gcc_obstack_init (&fake_var_decl_obstack);
}

tree parser::
cs_get_var (tree t)
{
	if (TREE_CODE (t) == MEM_REF) {
		t = TREE_OPERAND (t, 0);
		return cs_get_var (t);
	}
	return t;
}
//AN
//AN /* -------------------------------------------------------------------
//AN    Check whether the given alias is already present in the alias pool.
//AN    -------------------------------------------------------------------*/
//AN /*  bool
//AN check_alias_inclusion (constraint_t t, csvarinfo_t vi, unsigned int *loc)
//AN {
//AN    df_list ai;
//AN    for (ai=vi->constraints_with_vi_as_lhs; ai; ai=ai->next) {
//AN        if (constraint_equal (*t, *VEC_index (constraint_t, aliases, ai->val))) {
//AN            *loc = ai->val;
//AN            return true;
//AN        }
//AN    }
//AN    return false;
//AN }*/
//AN
//AN
//AN /* -----------------------------------------------------------------------------------
//AN    function to append the constraint index to the 'constriants_with_vi_as_lhs' of the
//AN    varinfo on the LHS of the constraint.
//AN    ----------------------------------------------------------------------------------*/
//AN /*  void
//AN append_constraint_to_varinfo (csvarinfo_t t, int alias_no)
//AN {
//AN          // DEBUG ("\n in append constraint to varinfo: %d",alias_no);
//AN
//AN     df_list elt = create_df_constraint (alias_no);
//AN     elt->next = t->constraints_with_vi_as_lhs;
//AN     t->constraints_with_vi_as_lhs = elt;
//AN }*/
//AN
//AN
//AN
//AN /*-------------------------------------------------------------------------
//AN   Insert the constraint t in the alias pool. Update the alias list for the
//AN   current basic block. Also, update the bb_alias_list of variable vi (forming
//AN   the LHS of the constraint) to reflect the fact that variable vi is the
//AN   lhs of some constraint t.
//AN   ------------------------------------------------------------------------*/
void parser::
insert_alias_in_pool (constraint_t t, csvarinfo_t vi, basic_block bb)
{
	DEBUG ("\nInsert in alias pool : %d,%d", vi->id, t->lhs.var);

	// df_list new_alias;         // Vini: Why commented out? Liveness set
	unsigned int loc;
	bool alias_found = false;// check_alias_inclusion (t, vi, &loc); // Vini: Why commented out?
	if (!alias_found) {
		//AH loc = VEC_size (constraint_t, aliases);
		//AH VEC_push_back (constraint_t, heap, aliases, t);
		loc = aliases.size();
		aliases.push_back (t);
		//append_constraint_to_varinfo (vi, loc);    // Vini: Why commented out? Adds to liveness set
	}
	//new_alias = create_df_constraint (loc);      // Vini: Why commented out? Adds to liveness set
	// Avantika has commented out the IF check, but not the ADD function
	// This is the difference in her code between Sep13 and Jan14
	// if (!compute_alias_and_pinfo)
	{
		DEBUG ("\ncompute_alias_and_pinfo != NULL");
		((block_information *)(bb->aux))->add_to_parsed_data_indices (loc, true, bb); // Add to constraints (or parsed data) of the block
	}
	//else             // Vini: Why commented out?
	{
		//append_to_fptr_constraints (new_alias);    // Vini: Why commented out?
		// DEBUG ("\nin fptr constraints add");
	}
}
//AN
//AN
//AN
//AN /*-------------------------------------------------------------------------------------
//AN   Function which processes the constraint t, retrieves the lhs and rhs of the pointsto
//AN   constraint, and updates the alias pool.
//AN   ------------------------------------------------------------------------------------*/
void parser::
cs_process_constraint (constraint_t t, basic_block bb)
{
	DEBUG ("\nin cs process constraint");

	struct constraint_expr rhs = t->rhs;
	struct constraint_expr lhs = t->lhs;

	// gcc_assert (rhs.var < VEC_size (csvarinfo_t, csvarmap));
	// gcc_assert (lhs.var < VEC_size (csvarinfo_t, csvarmap));
	gcc_assert (rhs.var < csvarmap.size());
	gcc_assert (lhs.var < csvarmap.size());

	if (!is_proper_var (lhs.var))
	{
		DEBUG ("\nlhs.var is not proper");
		return;
	}

	// ADDRESSOF on the lhs is invalid.
	gcc_assert (lhs.type != ADDRESSOF);

	if (check_deref)
		deref_stmt = (rhs.type == DEREF || lhs.type == DEREF);

	// Avantika has commented out the IF check, but not the INSERT function, Prashant does not
	// This is the difference in her code between Sep13 and Jan14
	// if (!compute_only_pinfo)
	insert_alias_in_pool (t, cs_get_varinfo (lhs.var), bb);

	/*  if (compute_alias_and_pinfo)
	 {
	  DEBUG ("\ncomput alias and pinfo");
	      //compute_stmt_out_1 (cpinfo, t);
	 }

	  if (compute_only_pinfo)
	 {
	 DEBUG ("\ncompute only pinfo");
	      //compute_stmt_out_2 (cpinfo, t);
	 }*/
}
//AN
//AN bool parser::
//AN possibly_deref (gimple stmt)
//AN {
//AN    tree lhsop = gimple_assign_lhs (stmt);
//AN    tree rhsop = (gimple_num_ops (stmt) == 2) ? gimple_assign_rhs1 (stmt) : NULL;
//AN
//AN    // Both Avantika and Prashant use this
//AN    //return ((TREE_CODE (lhsop) == MEM_REF) ||
//AN    //      (rhsop && TREE_CODE (rhsop) == MEM_REF));
//AN
//AN    return ((TREE_CODE (lhsop) == MEM_REF) ||
//AN            (rhsop && TREE_CODE (rhsop) == MEM_REF) ||
//AN            (TREE_CODE (lhsop) == COMPONENT_REF) ||
//AN            (rhsop && TREE_CODE (rhsop) == COMPONENT_REF));
//AN
//AN }
//AN
//AN
//AN /* --------------------------------------------------------------------
//AN    Perform necessary initializations for the callstrings pointsto pass.
//AN    -------------------------------------------------------------------*/
//AN
//AN /* Sudakshina: CHANGE DUE TO GCC-4.7.2 */
//AN
//AN /* Associate node with varinfo DATA. Worker for
//AN    cgraph_for_node_and_aliases.  */
//AN bool parser::
//AN associate_varinfo_to_alias (struct cgraph_node *node, void *data)
//AN {
//AN   if (node->alias || node->thunk.thunk_p)
//AN     cs_insert_vi_for_tree (node->decl, (csvarinfo_t)data);
//AN   return false;
//AN }
//AN
//AN
void parser::
process_gimple_assign_stmt (gimple stmt, basic_block bb, struct cgraph_node * cnode)
{
	DEBUG ("\nprocess_gimple_assign_stmt");
	tree lhsop = gimple_assign_lhs (stmt);
	tree rhsop = (gimple_num_ops (stmt) == 2) ? gimple_assign_rhs1 (stmt) : NULL;

	/*
	   RESULT ("\nSTATEMENT: ");
	   print_gimple_stmt(dump_file,stmt,0,0);
	   RESULT ("\n--------lhs--------\n");
	   print_node (dump_file, 0, lhsop, 0);
	   RESULT ("\n--------rhs--------\n");
	   print_node (dump_file, 0, rhsop, 0);

	   tree tt;
	   RESULT ("\n--------type-lhs--------\n");
	   if (tt = reference_alias_ptr_type (lhsop))
	      print_node (dump_file, 0, tt, 0);
	  if (TREE_CODE (lhsop) == MEM_REF)
	  {
	    RESULT ("\n----------MEM--------");
	    print_node (dump_file, 0, TREE_OPERAND (lhsop, 1), 0);
	  }

	   if (DECL_P (rhsop))
	   {
	   RESULT ("\n--------type-rhs--------\n");
	   if (tt = reference_alias_ptr_type (rhsop))
	      print_node (dump_file, 0, tt, 0);
	   }
	*/
#if DEBUG_CONTAINER
	RESULT ("\nSTATEMENT: ");
	print_gimple_stmt(dump_file, stmt, 0, 0);
	HOST_WIDE_INT bitsize = -1;
	HOST_WIDE_INT bitmaxsize = -1;
	HOST_WIDE_INT bitpos;
	get_ref_base_and_extent (lhsop, &bitpos, &bitsize, &bitmaxsize);
	DEBUG ("\n");
	print_gimple_stmt(dump_file, stmt, 0, 0);
	DEBUG ("\nlhsop bitpos=%lld, bitsize=%lld, bitmaxsize=%lld", bitpos, bitsize, bitmaxsize);
//   DEBUG ("\n--------lhs--------\n");
//   print_node (dump_file, 0, lhsop, 0);
//   DEBUG ("\n--------rhs--------\n");
//   print_node (dump_file, 0, rhsop, 0);
#endif

	if (rhsop && TREE_CLOBBER_P (rhsop))
		return;

	// FIXME: (field_must_have_pointers (lhsop) || field_must_have_pointers (rhsop)
	// For example, x=*y, here lhsop is int (neither mem_ref, nor pointer_type),
	// If the constraint of such a statement should be stored, use above condition

	if (field_must_have_pointers (lhsop))
	{
		DEBUG ("\nmust have pointers lhs");
		vector<ce_s> lhsc;
		// lhsc.create (200);
		vector<ce_s> rhsc;
		// rhsc.create (200);
		// VEC(ce_s, heap) *lhsc = NULL;
		// VEC(ce_s, heap) *rhsc = NULL;
		if (rhsop && AGGREGATE_TYPE_P (TREE_TYPE (lhsop)))  /* Look into : Structure variables */
		{
			DEBUG ("\naggregate_type_p");
			cs_do_structure_copy (lhsop, rhsop, bb, cnode);
		}
		else
		{
			DEBUG ("\nnot aggregate_type_p");
			cs_get_constraint_for (lhsop, &lhsc, bb, cnode);
			if (gimple_assign_rhs_code (stmt) == POINTER_PLUS_EXPR)
			{
				//AN DEBUG ("\nrhs is POINTER_PLUS_EXPR");
				DEBUGA ("\nrhs is POINTER_PLUS_EXPR") //AN
				// gimple_assign_rhs2() returns UNKNOWN_OFFSET times the operand value.
				cs_get_constraint_for_ptr_offset (gimple_assign_rhs1 (stmt),
				                                  gimple_assign_rhs2 (stmt), &rhsc, bb, cnode);
			}
			// Commented by Prashant
			//else if (code == BIT_AND_EXPR
			//        && TREE_CODE (gimple_assign_rhs2 (t)) == INTEGER_CST)
			//{
			// Aligning a pointer via a BIT_AND_EXPR is offsetting
			//   the pointer.  Handle it by offsetting it by UNKNOWN.
			//   get_constraint_for_ptr_offset (gimple_assign_rhs1 (t), NULL_TREE, &rhsc);
			//}
			else if ((CONVERT_EXPR_CODE_P (gimple_assign_rhs_code (stmt))
			          && !(POINTER_TYPE_P (gimple_expr_type (stmt))
			               && !POINTER_TYPE_P (TREE_TYPE (rhsop))))
			         || gimple_assign_single_p (stmt))
			{
				DEBUG ("\npointer_type_p ??");

				// cs_get_constraint_for (rhsop, &rhsc, bb, cnode); // by Prashant
				cs_get_constraint_for_rhs (rhsop, &rhsc, bb, cnode);
#if DEBUG_CONTAINER
				struct constraint_expr *rhsp;
				unsigned j;
				FOR_EACH_VEC_ELT (ce_s, rhsc, j, rhsp) {
					DEBUG ("\nrhsp %d offset %llu\n", rhsp->var, rhsp->offset);
				}
#endif
			}
			// cs_process_all_all_constraints calls
			// cs_process_constraint calls
			// insert_alias_in_pool. This function stores constraints in a global
			// variable: aliases (of type constraint_t).

			DEBUG ("\nin process_gimple_asgn_stmt\n");
			cs_process_all_all_constraints (lhsc, rhsc, bb);
		}

		// Commented by Prashant
		// If there is a store to a global variable the rhs escapes.
		// ...

		VEC_free (ce_s, heap, rhsc);
		VEC_free (ce_s, heap, lhsc);

#if DEBUG_CONTAINER
		print_assignment_data ();
#endif
	}

	// Constraints for v=*w type of statements is not created (where v is
	// non-pointer). However, w should be made live because w is a pointer.

	// MEM_REF: These nodes are used to represent the object pointed to by a
	// pointer offset by a constant. The first operand is the pointer being
	// dereferenced; it will always have pointer or reference type. The second
	// operand is a pointer constant. Its type is specifying the type to be used
	// for type-based alias analysis.
	else
	{
		// Let us say the statement is x->f=y. The control has reached this
		// point if x->f and y are non-pointers. However, generate liveness of
		// x.
		if (lhsop && TREE_CODE (lhsop) == COMPONENT_REF)
		{
			DEBUG ("\nlhs is COMPONENT_REF");
			lhsop = TREE_OPERAND (lhsop, 0);
		}

		// Generate liveness of lhs
		if (lhsop && TREE_CODE (lhsop) == MEM_REF)
		{
			DEBUG ("\nGenerate liveness constraint for lhs -- MEM_REF %d, %s(%d) in bb=%d",
			       field_must_have_pointers (lhsop),
			       (cs_get_vi_for_tree (cs_get_var (lhsop), bb, cnode))->name,
			       (cs_get_vi_for_tree (cs_get_var (lhsop), bb, cnode))->id,
			       bb->index);

			// Added by Vini
			tree lhsvar = cs_get_var (lhsop);
			// If lhs has ADDR_EXPR, then also field_must_have_pointers(lhsvar)
			// returns true. But we do not want to add lhsvar if it has been
			// used as lhsvar=...;
			if (!field_must_have_pointers (lhsvar) || TREE_CODE (lhsvar) == ADDR_EXPR)
				return;

			DEBUG ("\ngenerate liveness lhsvar");
			// generate_liveness_constraint
			((block_information *)(bb->aux))->add_to_parsed_data_indices
			((cs_get_vi_for_tree (lhsvar, bb, cnode))->id, false, bb);
		}

		// Let us say the statement is x=y->f. The control has reached this
		// point if x and y->f are non-pointers. However, generate liveness of
		// y.
		if (rhsop && TREE_CODE (rhsop) == COMPONENT_REF)
		{
			DEBUG ("\nrhs is COMPONENT_REF");
			rhsop = TREE_OPERAND (rhsop, 0);
		}

		// Generate liveness of rhs
		if (rhsop && TREE_CODE (rhsop) == MEM_REF)
		{
			DEBUG ("\nGenerate liveness constraint for rhs -- MEM_REF %d, %s(%d) in bb=%d",
			       field_must_have_pointers (rhsop),
			       (cs_get_vi_for_tree (cs_get_var (rhsop), bb, cnode))->name,
			       (cs_get_vi_for_tree (cs_get_var (rhsop), bb, cnode))->id,
			       bb->index);

			// Added by Vini
			tree rhsvar = cs_get_var (rhsop);
			// If rhs has ADDR_EXPR, then also field_must_have_pointers(rhsvar)
			// returns true. But we do not want to add rhsvar if it has been
			// used as ...=&rhsvar;
			if (!field_must_have_pointers (rhsvar) || TREE_CODE (rhsvar) == ADDR_EXPR)
				return;

			DEBUG ("\ngenerate liveness rhsvar");
			// generate_liveness_constraint
			((block_information *)(bb->aux))->add_to_parsed_data_indices
			((cs_get_vi_for_tree (rhsvar, bb, cnode))->id, false, bb);
		}
	}
}
//AN
//AN
void parser::
process_gimple_condition(gimple stmt, basic_block bb, struct cgraph_node * cnode)
{
	struct constraint_expr *exp;
	unsigned i;

	tree op0 = gimple_cond_lhs (stmt);
	tree op1 = gimple_cond_rhs (stmt);

	if (field_must_have_pointers (op0) && TREE_CODE (op0) != ADDR_EXPR) {
		vector<ce_s> results;
		// VEC (ce_s, heap) *results = NULL;
		cs_get_constraint_for (op0, &results, bb, cnode);
		FOR_EACH_VEC_ELT1 (ce_s, results, i, exp)
		// DEBUG ("\ngenerate liveness for %d",exp->var);
		((block_information *)(bb->aux))->add_to_parsed_data_indices (exp->var, false, bb);  // generate_liveness_constraint
		VEC_free (ce_s, heap, results);
	}
	if (field_must_have_pointers (op1) && TREE_CODE (op1) != ADDR_EXPR) {
		vector<ce_s> results;
		// VEC (ce_s, heap) *results = NULL;
		cs_get_constraint_for (op1, &results, bb, cnode);
		FOR_EACH_VEC_ELT1 (ce_s, results, i, exp)
		// DEBUG ("\n%d generate liveness for",exp->var);
		((block_information *)(bb->aux))->add_to_parsed_data_indices (exp->var, false, bb);  // generate_liveness_constraint
		VEC_free (ce_s, heap, results);
	}

}
//AN
//AN /* Find out aliases for PHI statements. */
//AN
void parser::
process_gimple_phi_stmt (gimple stmt, basic_block bb, struct cgraph_node * cnode)
{
	// VEC(ce_s, heap) *lhsc = NULL;
	// VEC(ce_s, heap) *rhsc = NULL;
	vector<ce_s> lhsc;
	vector<ce_s> rhsc;
	struct constraint_expr *c;
	size_t i;
	unsigned int j;
	DEBUG ("\nin process phi statement");
#if DEBUG_CONTAINER
	print_gimple_stmt(dump_file, stmt, 0, 0);
#endif

	/* For a phi node, assign all the arguments to the result. */
	cs_get_constraint_for (gimple_phi_result (stmt), &lhsc, bb, cnode);
	DEBUG ("\nthe no of phi args: %d", gimple_phi_num_args(stmt));
	int rhsc_count = 0;
	for (i = 0; i < gimple_phi_num_args (stmt); i++)
	{
		++rhsc_count;
		DEBUG ("\nrhsc_count=%d", rhsc_count);
		DEBUG ("\ni=%d loop", i);
		tree strippedrhs = PHI_ARG_DEF (stmt, i);
		STRIP_NOPS (strippedrhs);
		cs_get_constraint_for (strippedrhs, &rhsc, bb, cnode);
		// for (j = 0; VEC_iterate (ce_s, lhsc, j, c); j++)
		j = 0;
		for(auto c = lhsc.begin(); c != lhsc.end(); ++c,++j)	
		// for (j = 0; lhsc.iterate(j, &c); j++)
		{
			DEBUG ("\nj=%d loop", j);
			// struct constraint_expr *c2; 5 lines below
			// while (VEC_size (ce_s, rhsc) > 0)
			while (rhsc.size() > 0)
			{
				DEBUG ("\nrhsc VEC loop");
				struct constraint_expr &c2 = rhsc.back(); //VEC_back (ce_s, rhsc);
				cs_process_constraint (new_constraint (*c, c2), bb);
				if (rhsc_count >= 2)
					connect_with_previous_phi (bb);
				// rhsc.back(); // VEC_pop (ce_s, rhsc);
				rhsc.pop_back();
				multi_rhs = true;
			}
		}
	}

	initialize_prev_of_first_phi (bb);

	multi_rhs = false;
	rhsc.clear();
	lhsc.clear();
	// VEC_free (ce_s, heap, rhsc);
	// VEC_free (ce_s, heap, lhsc);
}
//AN
void parser::
connect_with_previous_phi (basic_block block)
{
	DEBUG ("\nconnect_with_previous_phi");

	list<pair<unsigned int, bool> > parsed_data_indices =
	    ((block_information *)(block->aux))->get_parsed_data_indices ();

	list<pair<unsigned int, bool> >::reverse_iterator rit;
	rit = parsed_data_indices.rbegin ();
	if (rit == parsed_data_indices.rend ()) return;
	unsigned int back_index = (*rit).first;
	bool is_back_assignment = (*rit).second;
	if (!is_back_assignment) return;
	DEBUG ("\nFetched back_index %d", back_index);
	++rit;
	if (rit == parsed_data_indices.rend ()) return;
	unsigned int prev_index = (*rit).first;
	bool is_prev_assignment = (*rit).second;
	if (!is_prev_assignment) return;
	DEBUG ("\nFetched prev_index %d", prev_index);

	constraint_t back_assignment = VEC_index (constraint_t, assignment_data, back_index);
	constraint_t prev_assignment = VEC_index (constraint_t, assignment_data, prev_index);
	if (!back_assignment || !prev_assignment)
	{
		RESULT ("\nError: Cannot extract assignment index info");
		return;
	}
	back_assignment->previous_phi = prev_assignment;

#if DEBUG_CONTAINER
	DEBUG ("\nConnecting %d <- %d", prev_index, back_index);
	DEBUG ("\n");
	print_assignment_data (back_index);
	DEBUG ("\n");
	print_assignment_data (prev_index);
#endif
}
//AN
//AN /**
//AN  * PREVIOUS_PHI is set so that it can be indicated that these statements are
//AN  * not to be analyzed in sequence but as if they are in parallel. Since they
//AN  * are in parallel, the pointer information of lhs generated by a previously
//AN  * analyzed phi statement should not be killed by any other phi statement. If
//AN  * there exists a phi statement with the same lhs and rhs, then set
//AN  * previous_phi of the first phi satement, so that no killing is performed in
//AN  * the first phi statement also.
//AN  */
//AN
void parser::
initialize_prev_of_first_phi (basic_block block)
{
	DEBUG ("\nconnect_with_previous_phi");

	list<pair<unsigned int, bool> > parsed_data_indices =
	    ((block_information *)(block->aux))->get_parsed_data_indices ();

	list<pair<unsigned int, bool> >::iterator it;
	for (it = parsed_data_indices.begin (); it != parsed_data_indices.end (); it++)
	{
		unsigned int index = it->first;
		bool is_assignment = it->second;
		if (!is_assignment) return;
		constraint_t assignment = VEC_index (constraint_t, assignment_data, index);
		constraint_expr lhs = assignment->lhs;
		constraint_expr rhs = assignment->rhs;
		// Does there exist a phi statement with same lhs and rhs
		if (lhs.var == rhs.var &&
		        lhs.type == rhs.type &&
		        lhs.offset == rhs.offset)
		{
			// Fetch first phi statement
			it = parsed_data_indices.begin ();
			constraint_t first_assignment = VEC_index (constraint_t, assignment_data, it->first);
			// Set the previous_phi of the first phi statement
			first_assignment->previous_phi = assignment;
			// RESULT ("\nSet first previous_phi also, so that no killing happens");
			return;
		}
	}
}
//AN
bool parser::
is_gimple_endblock (gimple t)
{
	return (gimple_code (t) == GIMPLE_RETURN);
}
//AN
void parser::
generate_retval_liveness (gimple stmt, basic_block bb, struct cgraph_node * cnode)
{
	DEBUG ("\ngenerate_retval_liveness ()");
	// tree retval = gimple_return_retval (stmt);
	tree retval = gimple_return_retval (dyn_cast<greturn*>(stmt));

	if (retval != NULL_TREE && field_must_have_pointers (retval)) {
		DEBUG ("\nNot pointer type");
		vector<ce_s> rhsc; // VEC(ce_s, heap) *rhsc = NULL;
		struct constraint_expr *rhs;
		unsigned int i;

		cs_get_constraint_for (retval, &rhsc, bb, cnode);
		// cs_get_constraint_for (retval, &rhsc, bb, cnode);
		FOR_EACH_VEC_ELT1 (ce_s, rhsc, i, rhs)
		{
			((block_information *)(bb->aux))->add_to_parsed_data_indices (rhs->var, false, bb);   // generate_liveness_constraint
			DEBUG ("\nPushed rhs->var %d", rhs->var);
		}
	}
}
//AN
/* Iterate over all the PHI nodes of the basic block and
   calculate alias info for them. */
bool parser::
process_phi_pointers (basic_block bb, struct cgraph_node * cnode)
{
	gimple_stmt_iterator gsi;
	DEBUG ("\nin process phi pointers");

	bool has_phi = false;
	// There could be more than one PHI statements in a block.
	// (test-cases/test60.c). Iterate over all.
	for (gsi = gsi_start_phis (bb); !gsi_end_p (gsi); gsi_next (&gsi)) {
#if DEBUG_CONTAINER
		DEBUG ("\nprocessing phi:");
		print_gimple_stmt (dump_file, gsi_stmt(gsi), 0, 0);
#endif
		gimple phi = gsi_stmt (gsi);
		tree phi_result = gimple_phi_result (phi);
		if (is_gimple_reg (phi_result)) {
			if (field_must_have_pointers (phi_result)) {
				DEBUG ("\nis_gimple_reg and field_must_have_pointers");
				has_phi = true;
				process_gimple_phi_stmt (phi, bb, cnode);
			}
		}
	}
	DEBUG ("\nReturn of phi pointer is %d", has_phi);
	return has_phi;
}
//AN
//AN
//AN /*--------------------------------------------------------------------
//AN   Returns the called function's decl tree. If it is a direct function
//AN   call, the TREE_CODE of the returned decl will be FUNCTION_DECL. If
//AN   it is a call via function pointer, it will be VAR_DECL.
//AN   -------------------------------------------------------------------*/
tree parser::
get_called_fn_decl (gimple stmt)
{
	/* If we can resolve it here, its a simple function call. */
	tree decl = gimple_call_fndecl (stmt);
	/* The call is through function pointer. */
	if (!decl)
		decl = gimple_call_fn (stmt);
	return decl;
}
//AN
//AN bool parser::
//AN is_function_pointer (basic_block call_site)
//AN {
//AN    // FIXME: check that this a call_site has only one statement.
//AN    gimple_stmt_iterator gsi = gsi_start_bb (call_site);
//AN    gimple statement = gsi_stmt (gsi);
//AN
//AN    return gimple_call_fndecl (statement) == NULL;
//AN }
//AN
gimple_stmt_iterator parser::
split_bb_at_stmt (basic_block & bb, gimple stmt)
{
	/// DEBUG ("\n---SPLIT---");
	/// DEBUG ("\nFirst statement of block %d (before split): ", bb->index);
#if DEBUG_CONTAINER
	if (!gsi_end_p (gsi_start_bb (bb)))
		print_gimple_stmt (dump_file, gsi_stmt (gsi_start_bb (bb)), 0, 0);
#endif
	edge e = split_block (bb, stmt);
	bb = e->dest;
	/// DEBUG ("\nFirst statement of block %d (after split): ", bb->index);
#if DEBUG_CONTAINER
	if (!gsi_end_p (gsi_start_bb (bb)))
		print_gimple_stmt (dump_file, gsi_stmt (gsi_start_bb (bb)), 0, 0);
#endif
	/// DEBUG ("\nInitializing split block %d", bb->index);
	initialize_block_aux (bb);
	return gsi_start_bb (bb);
}
//AN
void parser::
initialization (void)
{
	struct cgraph_node * cnode = NULL;
	symtab_node * node = NULL;  //KO NEWADD
	// init_alias_heapvars ();
	cs_init_alias_vars (cnode);
	bool is_first_cnode = true;

	//KO for (cnode = cgraph_nodes; cnode; cnode = cnode->next) {
	FOR_EACH_DEFINED_FUNCTION (cnode) {                         //KO NEWADD
		//KO cgraph_node *cnode=dyn_cast <cgraph_node *> (node);

		struct cgraph_node *alias;
		csvarinfo_t vi;

		/* Nodes without a body, and clone nodes are not interesting. */
		// if (!gimple_has_body_p (cnode->decl) || cnode->clone_of){
		if (!cnode->has_gimple_body_p () || cnode->clone_of) {
			continue;
		}
		cnode->get_body();

		// The first function is either main () or _GLOBAL__I_6535_0_test<..>.o ()

		// DEBUG ("\nin cnode --- %d,%s",cnode->uid,cgraph_node_name(cnode));
		/* locating main function. */
		//if (strcmp (cgraph_node_name (cnode), "int main()") == 0)
		if (strcmp (IDENTIFIER_POINTER (DECL_NAME (cnode->decl)), "main") == 0)
		{
			main_cnode = cnode;
			std::cerr << "initialization() : Got main" << std::endl;
			std::cerr << std::endl << "---------------------------------" << std::endl;
			print_node (stderr, 0, cnode->decl, 0);
			fflush (stderr);
			std::cerr << std::endl << "---------------------------------" << std::endl;
			DEBUG ("\nFound main function '%s'", IDENTIFIER_POINTER (DECL_NAME (cnode->decl)));
			DEBUG ("\nFound main function '%s'", cgraph_node_name (cnode));
			// cerr << "33333333333333333333333333333333" << FUNCTION_DECL_CHECK(main_cnode->decl)->function_decl.f << endl;
			// fprintf(stderr,"33333333333333333333333333333 %x",main_cnode->decl->function_decl.f);
			// print_node(stderr, 0, main_cnode->decl, 0);
			// struct function * fun = DECL_STRUCT_FUNCTION (main_cnode->decl);
			// if (fun == NULL)
			//     cerr << "00000000000000000" << endl;

		}
		// Creates csvarinfo_t for this function and its parameters and local variables
		vi = cs_create_func_info_for (cnode->decl, cgraph_node_name (cnode), cnode);

		/* Sudakshina: CHANGE due gcc-4.7.2 */
		// Sudakshina introduced this. Avantika uses it.
		// cgraph_for_node_and_aliases (cnode, associate_varinfo_to_alias, vi, true);

		/* Associate the varinfo node with all aliases.
		   for (alias = cnode->same_body; alias; alias = alias->next)
		   cs_insert_vi_for_tree (alias->decl, vi);*/

		is_first_cnode = false;
	}
}
//AN
//AN /**
//AN  * Global initializations of the form x=&y are not saved in any function. We
//AN  * need to add them to the first block of main function.
//AN  */
//AN // Added by Vini
void parser::
add_global_addressof_initializations ()
{
	push_cfun (DECL_STRUCT_FUNCTION (main_cnode->decl));
	basic_block startbb = get_start_block_of_function (main_cnode);
	basic_block bb = startbb->next_bb;
	// Create an empty block after START_BLOCK
	if (first_stmt (bb))
		split_bb_at_stmt (bb, NULL);
	else
		initialize_block_aux (bb);
	pop_cfun ();

	// Insert global initializations of the form x=&y in BB
	/// DEBUG ("\nadd_global_addressof_initializations (bb=%d)", bb->index);
	struct varpool_node * global_var;
	FOR_EACH_VARIABLE(global_var)// for (global_var = varpool_nodes; global_var; global_var = global_var->next)
	{
		if (field_must_have_pointers (global_var->decl))
		{
			csvarinfo_t globvar = cs_get_vi_for_tree (global_var->decl, bb, main_cnode);
			/// DEBUG ("\nAdded global_var %s(%d)", globvar->name, globvar->id);
		}
	}
}
//AN
//AN // Added by Vini
//AN static void
//AN study_loops ()
//AN {
//AN    DEBUG ("\nnumber_of_loops = %d", number_of_loops ());
//AN
//AN    // Studying loops
//AN    loop_iterator li;
//AN    struct loop * loop;
//AN    FOR_EACH_LOOP (li, loop, 0)
//AN    {
//AN        basic_block head = loop->header;
//AN        DEBUG ("\nheader block: %d", head->index);
//AN        basic_block * bbs;
//AN        bbs = get_loop_body (loop);
//AN        for (int i = 0; i < loop->num_nodes; i++)
//AN        {
//AN            basic_block bb = bbs[i];
//AN            DEBUG ("\nbb=%d, ", bb->index);
//AN
//AN            gimple_stmt_iterator gsi;
//AN            for (gsi = gsi_start_bb (bb); !gsi_end_p (gsi); gsi_next (&gsi))
//AN            {
//AN                gimple stmt = gsi_stmt (gsi);
//AN                print_gimple_stmt (dump_file, stmt, 0, 0);
//AN            }
//AN        }
//AN        free (bbs);
//AN    }
//AN
//AN    // Studying blocks
//AN    basic_block bb;
//AN    FOR_EACH_BB (bb)
//AN    {
//AN        for (loop = bb->loop_father; loop; loop = loop_outer (loop))
//AN        {
//AN            if (bb->index == loop->header->index)
//AN            {
//AN                DEBUG ("\nloop %d has header %d", loop->num, bb->index);
//AN            }
//AN        }
//AN    }
//AN }
//AN
//AN bool parser::
//AN is_loop_join (basic_block block)
//AN {
//AN    struct loop * loop = block->loop_father;
//AN    if (!loop)
//AN    {
//AN        RESULT ("\nError: loop_optimizer_init() not done");
//AN        return false;
//AN    }
//AN    bool loop_join = block->index == loop->header->index;
//AN    if (loop_join)
//AN        DEBUG ("\nBlock %d is header of loop %d\n", block->index, loop->num);
//AN
//AN    return loop_join;
//AN }
//AN
void parser::
preprocess_control_flow_graph ()
{
	CERR (preprocess_control_flow_graph STARTED % % % % % % % % % % % % % % % );
#if DEBUG_CONTAINER
	FUNCTION_NAME ();
#endif

	// Insert constraints corresponding to global initializations of the
	// form x=&y to the block after START_BLOCK of main_cnode.

	cerr << "+++++++++++++++" << endl;
	add_global_addressof_initializations ();
	cerr << "---------------" << endl;

	struct cgraph_node * cnode;
	FOR_EACH_DEFINED_FUNCTION (cnode) //for (cnode = cgraph_nodes; cnode; cnode = cnode->next)
	{
		CERR (preprocess_control_flow_graph 1 % % % % % % % % % % % % % % % );
		// Nodes without a body, and clone nodes are not interesting.
		if (!gimple_has_body_p (cnode->decl) || cnode->clone_of)
			continue;

		push_cfun (DECL_STRUCT_FUNCTION (cnode->decl));
		// set_cfun (DECL_STRUCT_FUNCTION (cnode->decl));
		// current_function_decl = cnode->decl;
		CERR (preprocess_control_flow_graph 2 % % % % % % % % % % % % % % % );

#if LOOP_MERGE_OPTIMIZATION
		// https://gcc.gnu.org/onlinedocs/gccint/Loop-representation.html

		// loop_optimizer_init (0);
		// loop_optimizer_init (LOOPS_MAY_HAVE_MULTIPLE_LATCHES);
		loop_optimizer_init (AVOID_CFG_MODIFICATIONS);
#endif

#if DEBUG_CONTAINER
		DEBUG ("\nFunction : %s\n", cgraph_node_name (cnode));
		if (!cfun)
			RESULT ("\nError: cfun is NULL");
		study_loops ();
#endif
		CERR (preprocess_control_flow_graph 3 % % % % % % % % % % % % % % % );

		// START_BLOCK
		basic_block startbb = get_start_block_of_function (cnode);
		DEBUG ("\nBlock %d is set as start block", startbb->index);
		initialize_block_aux (startbb);
		((block_information *)(startbb->aux))->set_block_type (START_BLOCK);

		// END_BLOCK
		basic_block endbb = get_end_block_of_function (cnode);
		DEBUG ("\nBlock %d is set as end block", endbb->index);
		initialize_block_aux (endbb);
		((block_information *)(endbb->aux))->set_block_type (END_BLOCK);
		CERR (preprocess_control_flow_graph 4 % % % % % % % % % % % % % % % );

		DEBUG ("\nstartbb=%d, endbb=%d", startbb->index, endbb->index);

		basic_block current_block;
		FOR_EACH_BB_FN (current_block, cfun)
		{
			CERR (preprocess_control_flow_graph 5 % % % % % % % % % % % % % % % );
			DEBUG ("\nBlock %d", current_block->index);

			gimple_stmt_iterator gsi;
			bool has_phi = false;

			// Initialize auxillary info.
			DEBUG ("\nInitializing block");
			initialize_block_aux (current_block);

#if LOOP_MERGE_OPTIMIZATION
			if (is_loop_join (current_block))
				((block_information *)(current_block->aux))->set_loop_join ();
#endif

			DEBUG ("\nprocess_phi_pointers block %d", current_block->index);
			has_phi = process_phi_pointers (current_block, cnode);
			DEBUG ("\nblock %d has_phi=%d", current_block->index, has_phi);

			CERR (preprocess_control_flow_graph 5 % % % % % % % % % % % % % % % );

			// Iterate over the statements of current_block.
			for (gsi = gsi_start_bb (current_block); !gsi_end_p (gsi); gsi_next (&gsi))
			{
				gimple stmt = gsi_stmt (gsi);
				DEBUG ("\n---------------------------------------\n");
				DEBUG ("\nProcessing statement in block %d: ", current_block->index);
#if DEBUG_CONTAINER
				print_gimple_stmt (dump_file, stmt, 0, 0);
#endif

				// We are assuming that END block has only
				// return statement; therefore, we use IN
				// points-to value, instead of OUT points-to
				// value. Thus, break at boundaries of callbb
				// and returnbb.
				if (is_gimple_call (stmt) || is_gimple_endblock (stmt))
				{
					DEBUG ("\nCall or end block");
					gimple_stmt_iterator origgsi = gsi;
					tree decl = NULL;

					// Need not break in case of library routines.
					if (is_gimple_call (stmt))
					{
						DEBUG ("\nCall statement");
						// FIXME: Make sure call statement is the only statement
						// in the CALL block.
						gimple_stmt_iterator origgsi_lib = gsi;
						gsi_prev (&gsi);
						if (!gsi_end_p (gsi))
						{
							DEBUG ("\nsplit 1");
							gsi = split_bb_at_stmt (current_block, gsi_stmt (gsi));
							// This block does not have PHI
							has_phi = false;
						}
						else
							gsi = origgsi_lib;

						// If block is not split after PHI statement, then
						// check if (has_phi) then split.
						// If there are PHI statements in this block, split.
						// test-cases/test53b.c
						// fp_1 = PHI (foo, bar); fp_1 ();
						// We want to have only the call statement in a block.
						// However, PHI is not identified as a statement.
						// Therefore, we split the block if there is a PHI
						// statement before the call statement.
						if (has_phi)
						{
							has_phi = false;
							DEBUG ("\nsplit after phi");
							split_bb_at_stmt (current_block, NULL);
							DEBUG ("block %d has_phi=%d", current_block->index, has_phi);
						}

						decl = get_called_fn_decl (stmt);
						if (TREE_CODE (decl) == FUNCTION_DECL)
						{
							DEBUG ("\nFunction decl");
							if (!DECL_STRUCT_FUNCTION (decl))
							{
								// FIXME: lbm benchmark, function MAIN_FINALIZE(),
								// <bb 6> LBM_freeGrid () wrongly considered
								// as a library call.
								DEBUG ("\nLibrary call");
								process_library_call (stmt, current_block, cnode);
								// A library call is not marked as a call_block
								continue;
							}
						}
					}

					DEBUG ("\nReached");
					gsi_prev (&gsi);
					if (!gsi_end_p (gsi))
					{
						DEBUG ("\nsplit 2");
						// Split before the call/return stmt.
						gsi = split_bb_at_stmt (current_block, gsi_stmt (gsi));
					}

					// Split the call into a new current_block if its not the back stmt.
					// origgsi = gsi;
					gsi = origgsi;
					gsi_next (&gsi);
					// if (!gsi_end_p (gsi)) // This is erroneous. The following is needed.
					if (!is_gimple_endblock (stmt) && !gsi_end_p (gsi))
					{
						DEBUG ("\nSplit after block");
						gsi = origgsi;
						split_block (current_block, gsi_stmt (gsi));
					}
					else
						gsi = origgsi;

					if (is_gimple_call (stmt))
					{
						DEBUG ("\nCall statement again");
						bool fptr_call = (TREE_CODE (decl) != FUNCTION_DECL);

						// Mark the calling function pointer as live.
						if (fptr_call)
						{
							unsigned int var = cs_get_vi_for_tree (decl, current_block, cnode)->id;
							// generate_liveness_constraint
							((block_information *)(current_block->aux))->add_to_parsed_data_indices (var, false, current_block);
						}

						// Mark call current_block with its properties.
						((block_information *)(current_block->aux))->set_block_type (CALL_BLOCK);
						DEBUG ("\nSet block type of %d to CALL_BLOCK", current_block->index);

						DEBUG ("\nDiscovering the static call argument mapping");
						// Discover the static call argument mapping.
						map_arguments_at_call (stmt, decl, fptr_call, current_block, cnode);
#if DEBUG_CONTAINER
						print_assignment_data ();
#endif

						// No need to create RETURN_BLOCK
						//DEBUG ("\nCreating empty return block");
						// Create an empty return block.
						//gsi = split_bb_at_stmt (current_block, gsi_stmt (gsi));
						//((block_information *)(current_block->aux))->set_block_type (RETURN_BLOCK);
						//break;
					}

					if (is_gimple_endblock (stmt))
					{
						DEBUG ("\nReturn block");
						generate_retval_liveness (stmt, current_block, cnode);
						// ((block_information *)(current_block->aux))->set_block_type (END_BLOCK);
					}
				}

				// Inspect other statements for possible pointers.
				else if (is_gimple_assign (stmt))
				{
					DEBUG ("\nAssignment statement");

					// FIXME:
					// Without block splitting: lbm runs in 726 seconds,
					// and produces 512252 lines of output.
					// With block splitting: lbm runs in 394 seconds,
					// and produces 2630260 lines of output.
					// Perhaps the ordering of function calls differs which
					// helps in this case.

					// Split in case of possible deref statement.
					// This is required if we want to give each field
					// in the statement a unique statement id.
#if SPLIT_DEREF
 #if SPLIT_ALL == 0
 					if (possibly_deref (stmt))
 #endif
 					{
 						gimple_stmt_iterator origgsi = gsi;
 						gsi_prev (&gsi);
 						if (!gsi_end_p (gsi))
 						{
 							DEBUG ("\nStatement before current statement (before split): ");
 #if DEBUG_CONTAINER
 							print_gimple_stmt (dump_file, gsi_stmt(gsi), 0, 0);
 #endif
 							gsi = split_bb_at_stmt (current_block, gsi_stmt (gsi));
 							DEBUG ("\nCurrent statement (after split): ");
 #if DEBUG_CONTAINER
 							print_gimple_stmt (dump_file, gsi_stmt(gsi), 0, 0);
 #endif
 						}
 						else
 							gsi = origgsi;
 					}
#endif

					check_deref = true;
					process_gimple_assign_stmt (stmt, current_block, cnode);
					check_deref = false;
				}

				else if (gimple_code (stmt) == GIMPLE_COND)
				{
					DEBUG ("\nCondition statement");
#if SPLIT_ALL
					gimple_stmt_iterator origgsi = gsi;
					gsi_prev (&gsi);
					if (!gsi_end_p (gsi))
						gsi = split_bb_at_stmt (current_block, gsi_stmt (gsi));
					else
						gsi = origgsi;
#endif
					process_gimple_condition (stmt, current_block, cnode);
				}

				/*
				// Check if the call/return stmt is the first stmt in the current_block.
				if (gsi_end_p (gsi) || gimple_code (gsi_stmt (gsi)) == GIMPLE_LABEL)
				{
				    DEBUG ("\nLabel statement");
				    if (has_phi)
				    {
				        gsi = split_bb_at_stmt (current_block, NULL);
				        has_phi = false;
				     }
				     else
				        gsi = origgsi;
				}
				*/
				else
				{
					DEBUG ("\nWhat is this?");
				}
				DEBUG ("\nNext statement");
				DEBUG ("block %d has_phi=%d", current_block->index, has_phi);
			}
			DEBUG ("\nNext block");
		}

		// if (dump_file)// && !ipacs_time)
		// gimple_dump_cfg (dump_file, dump_flags);

		// Return block has is_gimple_endblock (stmt) true.
		// If the function does not have a return block, then fake
		// return statement is inserted by gimple.
		// If the function does not have a return block and has exit
		// blocks, then no return statement is inserted.
		// FIXME: In this case, we use EXIT_BLOCK_PTR_FOR_FUNCTION.
		// However, I realized that it fetches only one of the exit()
		// blocks and not the rest. Therefore, evaluation of the
		// control flow paths ending at the rest of the exit() blocks
		// does not happen. For example, in liveness analysis of
		// sjeng.c main function, free_hash() and free_ecache() never
		// get evaluated/

		// Prashant: If there was no endblock, mark it.
		// if (!endblock)
		// {
		//  endblock = EXIT_BLOCK_PTR_FOR_FUNCTION (DECL_STRUCT_FUNCTION (cnode->decl))->prev_bb;
		//  ((block_information *)(endblock->aux))->set_block_type (END_BLOCK);
		// }

		// Set the reverse postorder index for all the blocks.
		// rp = XNEWVEC (int, total_curr_blocks);
		// pre_and_rev_post_order_compute (NULL, rp, false);

		// Initialize the cgraph info.
		// initialize_cgraphaux_info (cnode, endblock, rp, total_curr_blocks);
		// free (rp);

#if LOOP_MERGE_OPTIMIZATION
		loop_optimizer_finalize ();
#endif
		pop_cfun();
	}

	CERR (preprocess_control_flow_graph ENDED % % % % % % % % % % % % % % % );
}
//AN
//AN /* ----------------------------------------------------------------
//AN    Restoring the cfg by clearing the aux field of each basic block
//AN    and removing unnecessary (split) blocks.
//AN    ---------------------------------------------------------------*/
//AN void parser::
//AN restore_control_flow_graph ()
//AN {
//AN #if DEBUG_CONTAINER
//AN    FUNCTION_NAME ();
//AN #endif
//AN
//AN    struct cgraph_node * cnode;
//AN    for (cnode = cgraph_nodes; cnode; cnode = cnode->next)
//AN    {
//AN        if (!gimple_has_body_p (cnode->decl) || cnode->clone_of)
//AN            continue;
//AN
//AN        push_cfun(DECL_STRUCT_FUNCTION (cnode->decl));
//AN        // current_function_decl = cnode->decl;
//AN        // set_cfun (DECL_STRUCT_FUNCTION (cnode->decl));
//AN
//AN        /* Free cgraph node's aux field. */
//AN        if (cnode->aux) {
//AN       DEBUG ("\nFreeing cnode->aux");
//AN            ggc_free (cnode->aux);
//AN            cnode->aux = NULL;
//AN        }
//AN        /* Free each bb's aux field. */
//AN        basic_block cbb;
//AN        FOR_EACH_BB (cbb) {
//AN            if (cbb->aux) {
//AN           DEBUG ("\nFreeing block->aux");
//AN                ggc_free (cbb->aux);
//AN           DEBUG ("\nFreed block->aux");
//AN                cbb->aux = NULL;
//AN            }
//AN        }
//AN
//AN        // Added by Vini
//AN    basic_block startbb = get_start_block_of_function (cnode);
//AN    basic_block endbb = get_end_block_of_function (cnode);
//AN        if (startbb->aux) {
//AN                DEBUG ("\nFreeing block->aux");
//AN                ggc_free (startbb->aux);
//AN           DEBUG ("\nFreed block->aux");
//AN                startbb->aux = NULL;
//AN            }
//AN         if (endbb->aux) {
//AN                DEBUG ("\nFreeing block->aux");
//AN                ggc_free (endbb->aux);
//AN           DEBUG ("\nFreed block->aux");
//AN                endbb->aux = NULL;
//AN            }
//AN
//AN        /* Merge bb's if necessary. */
//AN        DEBUG ("\ncleanup_tree_cfg ()");
//AN        cleanup_tree_cfg ();
//AN        /* Free the dominator info. */
//AN        free_dominance_info (CDI_DOMINATORS);
//AN        free_dominance_info (CDI_POST_DOMINATORS);
//AN
//AN        pop_cfun ();
//AN    }
//AN }
//AN
void parser::
initialize_block_aux (basic_block block)
{
	// block->aux = (block_information *) ggc_alloc_cleared_atomic (sizeof (block_information));
	if (block->aux)
		return;
	block->aux = new block_information ();
	/// DEBUG ("\nAllocated new aux to block %d", block->index);
}
//AN
void parser::
delete_parsed_data (basic_block block)
{
	DEBUG ("\nDeleting parsed data of block %d", block->index);

	list<pair<unsigned int, bool> > parsed_data_indices =
	    ((block_information *)(block->aux))->get_parsed_data_indices ();

	// Multiple parsed indices may point to the same offset_sequence. For
	// example, struct node x=y->g; creates parsed assignments: x.0=y->g,
	// x.32=y->g, x.64=y->g... All these have the same rhs (and therefore
	// same offset_sequence). Therefore, first collect all offset_sequence
	// and then delete them.
	set<list<unsigned int> *> set_of_offset_sequence;

	list<pair<unsigned int, bool> >::iterator it;
	for (it = parsed_data_indices.begin (); it != parsed_data_indices.end (); it++)
	{
		unsigned int index = (*it).first;
		bool is_assignment = (*it).second;
		DEBUG ("\nDelete: Parsed data: index %d, bool %d, block %d, ",
		       index, is_assignment, block->index);

		if (!is_assignment)
			continue;

		constraint_t assignment = assignment_data[index]; //VEC_index (constraint_t, assignment_data, index);
		DEBUG ("\nDelete assignment index=%d, addr=%x", index, assignment);
		constraint_expr lhs = assignment->lhs;
		constraint_expr rhs = assignment->rhs;
#if DEBUG_CONTAINER
		print_assignment_data (index);
#endif

		DEBUG ("\nGC parsed data");
		if (lhs.offset_sequence)
		{
			DEBUG ("\nDeallocate lhs.offset_sequence(addr=%x)",
			       lhs.offset_sequence);
			set_of_offset_sequence.insert (lhs.offset_sequence);
			lhs.offset_sequence = NULL;
		}
		if (rhs.offset_sequence)
		{
			DEBUG ("\nDeallocate rhs.offset_sequence(addr=%x)",
			       rhs.offset_sequence);
			set_of_offset_sequence.insert (rhs.offset_sequence);
			rhs.offset_sequence = NULL;
		}
	}

#if GC
	set<list<unsigned int> *>::iterator si;
	for (si = set_of_offset_sequence.begin (); si != set_of_offset_sequence.end (); si++)
	{
		DEBUG ("\nDelete offset_sequence=%x", *si);
		if (*si)
			delete *si;
	}
#endif
}

void parser::
delete_block_aux()
{
	struct cgraph_node * cnode;
	//KO for (cnode = cgraph_nodes; cnode; cnode = cnode->next)
	FOR_EACH_DEFINED_FUNCTION (cnode)
	{
		if (!gimple_has_body_p (cnode->decl) || cnode->clone_of)
			continue;
		//KO push_cfun (DECL_STRUCT_FUNCTION (cnode->decl));
		struct function *func = DECL_STRUCT_FUNCTION (cnode->decl); //KO NEWADD
		push_cfun (func); //KO NEWADD

		basic_block bb;
		//KO FOR_EACH_BB (bb) {
		FOR_EACH_BB_FN (bb, func) {  //KO NEWADD
			if (bb->aux)
			{

				delete_parsed_data (bb);
#if GC
				DEBUG ("\nGC block");
				delete (block_information *) bb->aux;
#endif
				bb->aux = NULL;
			}
		}

		bb = get_start_block_of_function (cnode);
		if (bb->aux)
		{
			delete_parsed_data (bb);
#if GC
			DEBUG ("\nGC block");
			delete (block_information *) bb->aux;
#endif
			bb->aux = NULL;
		}
		bb = get_end_block_of_function (cnode);
		if (bb->aux)
		{
			delete_parsed_data (bb);
#if GC
			DEBUG ("\nGC block");
			delete (block_information *) bb->aux;
#endif
			bb->aux = NULL;
		}

		pop_cfun();
	}
}
//AN
//AN
//AN gimple_stmt_iterator parser::
//AN split_block_at_statement (gimple statement, basic_block block)
//AN {
//AN    edge e = split_block (block, statement);
//AN    block = e->dest;
//AN
//AN    // Initialize the newly created basic block
//AN    initialize_block_aux (block);
//AN
//AN    return gsi_start_bb (block);
//AN }
//AN
//AN set<unsigned int> parser::
//AN get_global_variables ()
//AN {
//AN    set<unsigned int> global_vars;
//AN
//AN    DEBUG ("\nVariable data:");
//AN    for (unsigned int index = 0; index < VEC_size (csvarinfo_t, variable_data); index++)
//AN    {
//AN            csvarinfo_t variable = VEC_index (csvarinfo_t, variable_data, index);
//AN        if (is_proper_var (index) && global_var (index))
//AN        {
//AN                DEBUG ("\nVariable id %d, name %s, offset %llu",
//AN                variable->id, variable->name, variable->offset);
//AN            global_vars.insert (index);
//AN        }
//AN    }
//AN
//AN    return global_vars;
//AN }
//AN
//AN set<unsigned int> parser::
//AN get_global_named_pointers ()
//AN {
//AN    DEBUG ("\nget_global_named_variables ()");
//AN
//AN    set<unsigned int> global_vars;
//AN    for (unsigned int index = 0; index < VEC_size (csvarinfo_t, variable_data); index++)
//AN    {
//AN        if (!global_var (index))
//AN            continue;
//AN
//AN            csvarinfo_t gvar = VEC_index (csvarinfo_t, variable_data, index);
//AN            DEBUG ("\nVariable id %d, name %s, offset %llu",
//AN            gvar->id, gvar->name, gvar->offset);
//AN
//AN        if (gvar->id <= 3)
//AN            continue;
//AN
//AN        if (gvar && gvar->decl && TREE_CODE (gvar->decl) == FUNCTION_DECL)
//AN            continue;
//AN
//AN        if (gvar->is_heap_var)
//AN            continue;
//AN
//AN        if (!field_must_have_pointers (gvar->decl))
//AN            continue;
//AN
//AN        global_vars.insert (index);
//AN    }
//AN
//AN    return global_vars;
//AN }
//AN
//AN set<unsigned int> parser::
//AN get_function_arguments (basic_block call_site, struct cgraph_node * src_function)
//AN {
//AN    // FIXME: check that this a call_site has only one statement.
//AN    gimple_stmt_iterator gsi = gsi_start_bb (call_site);
//AN    gimple call_stmt = gsi_stmt (gsi);
//AN #if DEBUG_CONTAINER
//AN    DEBUG ("\ncall_stmt: ");
//AN    print_gimple_stmt (dump_file, call_stmt, 0, 0);
//AN    DEBUG ("\ngimple_call_num_args = %d", gimple_call_num_args (call_stmt));
//AN #endif
//AN    set<unsigned int> args;
//AN    for (int j = 0; j < gimple_call_num_args (call_stmt); j++) {
//AN        tree arg = gimple_call_arg (call_stmt, j);
//AN        if (field_must_have_pointers (arg)) {
//AN                VEC (ce_s, heap) *results = NULL;
//AN                cs_get_constraint_for (arg, &results, call_site, src_function);
//AN                   struct constraint_expr *exp;
//AN                unsigned i;
//AN                FOR_EACH_VEC_ELT (ce_s, results, i, exp)
//AN           {
//AN               DEBUG ("\narg_info %d", exp->var);
//AN           args.insert (exp->var);
//AN           }
//AN                VEC_free (ce_s, heap, results);
//AN        }
//AN    }
//AN    return args;
//AN }
//AN
//AN set<unsigned int> parser::
//AN get_function_parameters (struct cgraph_node * function)
//AN {
//AN    set<unsigned int> function_parameters;
//AN    tree args;
//AN    DEBUG ("\nParameters: ");
//AN    for (args = DECL_ARGUMENTS (function->decl); args; args = TREE_CHAIN (args))
//AN    {
//AN #if DEBUG_CONTAINER
//AN        const char * function_name = cgraph_node_name (function);
//AN        DEBUG ("\n%s arg: ", function_name);
//AN        print_node_brief (dump_file, "", args, 0);
//AN #endif
//AN        if (TREE_CODE(args) != PARM_DECL || is_global_var (args))
//AN        {
//AN            RESULT ("\nError: argument is not PARM_DECL");
//AN            continue;
//AN        }
//AN
//AN        function_parameters.insert (get_tree_index (args));
//AN    }
//AN    return function_parameters;
//AN }
//AN
//AN set<unsigned int> parser::
//AN get_local_variables (struct cgraph_node * function)
//AN {
//AN #if DEBUG_CONTAINER
//AN    FUNCTION_NAME ();
//AN #endif
//AN
//AN    // FIXME: Pathetic coding here:
//AN
//AN    set<unsigned int> local_variables;
//AN
//AN    for (int index = 0; index < VEC_size (csvarinfo_t, variable_data); index++)
//AN    {
//AN        csvarinfo_t variable = cs_get_varinfo (index);
//AN        struct cgraph_node * cnode = variable->scoping_function;
//AN        if (cnode && function == cnode && variable->decl
//AN            // Can this ever be the case?
//AN            && TREE_CODE(variable->decl) != PARM_DECL
//AN            // Can this ever be the case?
//AN            && !variable->is_global_var)
//AN            local_variables.insert (variable->id);
//AN #if DEBUG_CONTAINER
//AN        const char * function_name = NULL;
//AN        if (cnode)
//AN            function_name = cgraph_node_name (cnode);
//AN        DEBUG ("\nVariable id %d, name %s, offset %llu, scoping function %s",
//AN            variable->id, variable->name, variable->offset, function_name);
//AN #endif
//AN    }
//AN    return local_variables;
//AN
//AN #if 0
//AN    // FIXME: Pathetic coding here:
//AN
//AN    // BUG: FOR_EACH_LOCAL_DECL returns only z.0+32 tree out of
//AN    // {z.0+32,z.32+32,z.64+32}.
//AN
//AN    set<unsigned int> local_variables;
//AN    tree fn = function->decl;
//AN    unsigned u;
//AN    tree var;
//AN    DEBUG ("\nParser local variables: ");
//AN    FOR_EACH_LOCAL_DECL (DECL_STRUCT_FUNCTION (fn), u, var)
//AN    {
//AN        local_variables.insert (get_tree_index (var));
//AN #if DEBUG_CONTAINER
//AN        DEBUG ("\n");
//AN        print_node_brief (dump_file, "", var, 0);
//AN #endif
//AN    }
//AN    DEBUG ("\ndone");
//AN
//AN    return local_variables;
//AN #endif
//AN }
//AN
//AN /**
//AN  * This function inserts all non-temporary, non-parameter, non-global
//AN  * pointer variables of CURRENT_FUNCTION.
//AN  */
//AN
//AN set<unsigned int> parser::
//AN get_local_non_temp_pointers (struct cgraph_node * current_function)
//AN {
//AN    DEBUG ("\nget_local_non_temp_pointers");
//AN    DEBUG ("\nlocal_non_temp_pointers");
//AN
//AN    set<unsigned int> local_non_temp_pointers;
//AN    for (int index = 0; index < VEC_size (csvarinfo_t, variable_data); index++)
//AN    {
//AN        csvarinfo_t variable = cs_get_varinfo (index);
//AN        struct cgraph_node * cnode = variable->scoping_function;
//AN        if (cnode && current_function == cnode
//AN            && variable->decl
//AN            && !DECL_ARTIFICIAL (variable->decl)
//AN            && TREE_CODE(variable->decl) != PARM_DECL
//AN            && !variable->is_global_var
//AN            && field_must_have_pointers (variable->decl))
//AN        {
//AN            local_non_temp_pointers.insert (variable->id);
//AN #if DEBUG_CONTAINER
//AN            const char * function_name = NULL;
//AN            if (cnode)
//AN                function_name = cgraph_node_name (cnode);
//AN            DEBUG ("\nVariable id %d, name %s, offset %llu, scoping function %s",
//AN                variable->id, variable->name, variable->offset, function_name);
//AN #endif
//AN        }
//AN    }
//AN    return local_non_temp_pointers;
//AN }
//AN
//AN unsigned int parser::
//AN get_tree_index (tree v)
//AN {
//AN    //FIXME: Pathetic coding here:
//AN
//AN    for (int index = 0; index < VEC_size (csvarinfo_t, variable_data); index++)
//AN    {
//AN            csvarinfo_t variable = VEC_index (csvarinfo_t, variable_data, index);
//AN        if (variable->decl == v)
//AN        {
//AN #if DEBUG_CONTAINER
//AN            DEBUG ("\nVariable id %d, name %s, offset %llu", variable->id, variable->name, variable->offset);
//AN #endif
//AN            return variable->id;
//AN        }
//AN    }
//AN
//AN }
//AN
//AN void parser::
//AN handle_unknown_offset (constraint_expr & e)
//AN {
//AN    // if (e.offset == UNKNOWN_OFFSET)
//AN    //  RESULT ("\nError: offset = UNKNOWN_OFFSET");
//AN    // else
//AN    //  DEBUG ("\noffset = %llu", e.offset);
//AN
//AN    // FIXME: all UNKNOWN_OFFSET are not getting recognized. For example,
//AN    // hmmer, function regatom(), bb 18, D.20045_38 = D.20044_37 + -2;
//AN    // rhs.offset=2*UNKNOWN_OFFSET-192.
//AN
//AN    // FIXME: bzip2, function sendMTFValues, D.4498_1348 = &s_59(D)->len[t_13][0];
//AN    // The offset is UNKNOWN_OFFSET but pointer_arithmetic=0.
//AN
//AN #if 0
//AN    // In case of pointer arithmetic, offset is an integral multiple of
//AN    // UNKNOWN_OFFSET.
//AN    if (e.offset && e.offset % UNKNOWN_OFFSET == 0)
//AN    {
//AN            csvarinfo_t variable = VEC_index (csvarinfo_t, variable_data, e.var);
//AN        RESULT ("\ne.var=%s(%d), e.type=%d, e.ptr_arith=%d, e.offset=unknown_offset",
//AN            variable->name, e.var, e.type, e.pointer_arithmetic);
//AN    }
//AN #endif
//AN    if (e.pointer_arithmetic)
//AN    {
//AN            csvarinfo_t variable = VEC_index (csvarinfo_t, variable_data, e.var);
//AN        RESULT ("\ne.var=%s(%d), e.type=%d, e.ptr_arith=%d, e.offset=unknown_offset",
//AN            variable->name, e.var, e.type, e.pointer_arithmetic);
//AN    }
//AN }
//AN
void parser::
save_heap_location (gimple stmt, unsigned int heapvar)
{
	if (!stmt) return;
	if (!gimple_has_location (stmt)) return;
	expanded_location xloc = expand_location (gimple_location (stmt));
	heap_location[heapvar] = xloc;
}

//AN void parser::
//AN print_block_statements (basic_block block)
//AN {
//AN   RESULT ("\n");
//AN   gimple_stmt_iterator gsi;
//AN   for (gsi = gsi_start_bb (block); !gsi_end_p (gsi); gsi_next (&gsi))
//AN   print_gimple_stmt (dump_file, gsi_stmt (gsi), 0, 0);
//AN }
//AN
//AN bool parser::
//AN print_source_location (basic_block block)
//AN {
//AN    if (!block) return false;
//AN    gimple_stmt_iterator gsi = gsi_start_bb (block);
//AN    if (gsi_end_p (gsi)) return false;
//AN    gimple stmt = gsi_stmt (gsi);
//AN    if (!stmt) return false;
//AN    if (!gimple_has_location (stmt)) return false;
//AN    expanded_location xloc = expand_location (gimple_location (stmt));
//AN    RESULT ("\nFile %s, Line %d", xloc.file, xloc.line);
//AN    RESULT ("\n");
//AN    for (gsi = gsi_start_bb (block); !gsi_end_p (gsi); gsi_next (&gsi))
//AN        print_gimple_stmt (dump_file, gsi_stmt (gsi), 0, 0);
//AN
//AN    return true;
//AN }
//AN
void parser::
print_heap_location (csvarinfo_t variable)
{
	expanded_location xloc = heap_location[variable->id];
	RESULT (" -- File %s Line %d", xloc.file, xloc.line);
}

void parser::
print_variable_data ()
{
	RESULT ("\nVARIABLES\n=========\n");
	DEBUG ("\nVariable data:");
	DEBUG ("\npassed addr of program.variable_data=%x", variable_data);
	// for (int index = 0; index < VEC_size (csvarinfo_t, variable_data); index++)
	for (int index = 0; index < variable_data.size(); index++)
	{
		csvarinfo_t variable = variable_data[index]; //VEC_index (csvarinfo_t, variable_data, index);
		const char * function_name = NULL;
		if (variable && variable->scoping_function)
			function_name = cgraph_node_name (variable->scoping_function);
		DEBUG ("\nVariable id %d, name %s, offset %llu, function %s",
		       variable->id, variable->name, variable->offset, function_name);
		RESULT ("\n%s(%d)", variable->name, variable->id);
		if (variable->is_heap_var)
			print_heap_location (variable);
		else if (variable->decl)
			RESULT (" -- File %s Line %d",
			        DECL_SOURCE_FILE (variable->decl), DECL_SOURCE_LINE (variable->decl));
	}
	RESULT ("\n");
}

void parser::
print_assignment_data ()
{
	DEBUG ("\nAssignment data:");
	// for (int index = 0; index < VEC_size (constraint_t, assignment_data); index++)
	for (int index = 0; index < assignment_data.size(); index++)
	{
		constraint_t assignment = assignment_data[index]; //VEC_index (constraint_t, assignment_data, index);
		constraint_expr lhs = assignment->lhs;
		constraint_expr rhs = assignment->rhs;
		csvarinfo_t lhs_variable = variable_data[lhs.var]; //VEC_index (csvarinfo_t, variable_data, lhs.var);
		csvarinfo_t rhs_variable = variable_data[rhs.var]; //VEC_index (csvarinfo_t, variable_data, rhs.var);
		RESULT ("\nLHS: variable id %d, ptr_arith=%d, offset %llu(",
		        lhs.var, lhs.pointer_arithmetic, lhs.offset);
		list<unsigned int>::iterator ofi;
		if (lhs.offset_sequence)
			for (ofi = lhs.offset_sequence->begin (); ofi != lhs.offset_sequence->end (); ofi++)
				RESULT ("%d,", *ofi);
		RESULT ("), type %d, name %s",
		        lhs.type, lhs_variable->name);

		RESULT (" RHS: variable id %d, ptr_arith=%d, offset %llu(",
		        rhs.var, rhs.pointer_arithmetic, rhs.offset);
		if (rhs.offset_sequence)
			for (ofi = rhs.offset_sequence->begin (); ofi != rhs.offset_sequence->end (); ofi++)
				RESULT ("%d,", *ofi);
		RESULT ("), type %d, name %s",
		        rhs.type, rhs_variable->name);

	}
}
//AN
void parser::
print_variable_data (int index)
{
	csvarinfo_t variable = variable_data[index]; //VEC_index (csvarinfo_t, variable_data, index);
    RESULT ("Variable id %d, name %s, offset %llu", variable->id, variable->name, variable->offset);

	DEBUG ("\nNext field in structure:");
	csvarinfo_t vi;
	for (vi = variable; vi; vi = vi->next)
		RESULT ("\nVar id %d, name %s, offset %llu", vi->id, vi->name, vi->offset);
}

void parser::
print_assignment_data (int index)
{
	constraint_t assignment = assignment_data[index]; //VEC_index (constraint_t, assignment_data, index);
	RESULT ("\nassignment index=%d", index);
	constraint_expr lhs = assignment->lhs;
	constraint_expr rhs = assignment->rhs;
	csvarinfo_t lhs_variable = variable_data[lhs.var];//VEC_index (csvarinfo_t, variable_data, lhs.var);
	csvarinfo_t rhs_variable = variable_data[rhs.var];//VEC_index (csvarinfo_t, variable_data, rhs.var);
	RESULT ("\nLHS: variable id %d, ptr_arith=%d, offset %llu(",
	        lhs.var, lhs.pointer_arithmetic, lhs.offset);
	list<unsigned int>::iterator ofi;
	if (lhs.offset_sequence)
		for (ofi = lhs.offset_sequence->begin (); ofi != lhs.offset_sequence->end (); ofi++)
			RESULT ("%d,", *ofi);
	RESULT ("), type %d, name %s, RHS: variable id %d, ptr_arith=%d, offset %llu(",
	        lhs.type, lhs_variable->name,
	        rhs.var, rhs.pointer_arithmetic, rhs.offset);
	if (rhs.offset_sequence)
		for (ofi = rhs.offset_sequence->begin (); ofi != rhs.offset_sequence->end (); ofi++)
			RESULT ("%d,", *ofi);
	RESULT ("), type %d, name %s",
	        rhs.type, rhs_variable->name);
}

void parser::
print_parsed_data (basic_block current_block)
{
	DEBUG ("\nPrinting parsed data of block %d", current_block->index);

	list<pair<unsigned int, bool> > parsed_data_indices =
	    ((block_information *)(current_block->aux))->get_parsed_data_indices ();

	list<pair<unsigned int, bool> >::iterator it;
	for (it = parsed_data_indices.begin (); it != parsed_data_indices.end (); it++)
	{
		unsigned int index = (*it).first;
		bool is_assignment = (*it).second;
		RESULT ("\nParsed data: index %d, bool %d, block %d, ",
		        index, is_assignment, current_block->index);

		if (is_assignment)
			print_assignment_data (index);
		else
			print_variable_data (index);

        // RESULT ("\n========");
	}
}

void parser::
print_parsed_data ()
{
	DEBUG ("\nprint_parsed_data ()");
	DEBUG ("\nUNKNOWN_OFFSET %llu", UNKNOWN_OFFSET);

	struct cgraph_node * cnode = NULL;
	//KO for (cnode = cgraph_nodes; cnode; cnode = cnode->next)
	FOR_EACH_DEFINED_FUNCTION (cnode)                           //KO NEWADD
	{
		struct function *func;              //KO NEWADD
		// Nodes without a body, and clone nodes are not interesting.
		if (!gimple_has_body_p (cnode->decl) || cnode->clone_of)
			continue;


		//KO push_cfun(DECL_STRUCT_FUNCTION (cnode->decl));
		func = DECL_STRUCT_FUNCTION (cnode->decl);
		push_cfun(func);

		RESULT ("\n\nFunction : %s\n", cgraph_node_name (cnode));
		basic_block current_block;
		//KO FOR_EACH_BB (current_block)
		FOR_EACH_BB_FN (current_block, func) {
			print_parsed_data (current_block);
		}

		pop_cfun();
	}
}

void parser::
print_original_cfg ()
{
#if DEBUG_CONTAINER
	FUNCTION_NAME ();
#endif
	struct cgraph_node * cnode = NULL;
	// for (cnode = cgraph_nodes; cnode; cnode = cnode->next)
	FOR_EACH_DEFINED_FUNCTION (cnode) {                         //KO NEWADD
		// Nodes without a body, and clone nodes are not interesting.
		// if (!gimple_has_body_p (cnode->decl) || cnode->clone_of)
		// 	continue;
		// push_cfun(DECL_STRUCT_FUNCTION (cnode->decl));

		struct function *func;              //KO NEWADD
		// Nodes without a body, and clone nodes are not interesting.
		if (!gimple_has_body_p (cnode->decl) || cnode->clone_of)
			continue;


		//KO push_cfun(DECL_STRUCT_FUNCTION (cnode->decl));
		func = DECL_STRUCT_FUNCTION (cnode->decl);
		push_cfun(func);
// #if DEBUG_CONTAINER
		RESULT ("\nFunction : %s\n", cgraph_node_name (cnode));
// #endif
		int n = 1;
		basic_block current_block;
		FOR_EACH_BB_FN(current_block, func)// FOR_EACH_BB (current_block)
		{
			RESULT ("\n<bb %d>\n", current_block->index);
			gimple_stmt_iterator gsi;
// #if DEBUG_CONTAINER
			for (gsi = gsi_start_bb (current_block); !gsi_end_p (gsi); gsi_next (&gsi))
			{
				//AN RESULT ("%d: ", n++);
				RESULT ("  ", n++);
				print_gimple_stmt (dump_file, gsi_stmt (gsi), 0, 0);
			}
// #endif
		}
		pop_cfun();
	}
}
