
#include <iostream>     // Anshuman: tmp included for diagnostic std::cerr msgs

// #include <algorithm>	// Should be used before gcc-plugin.h

/*------------------------------------------------------------------------------
 * STRONG DEPENDENCIES: START (Anshuman: Order is important)
 *----------------------------------------------------------------------------*/
#include <sstream>      // sstream ==> gcc-plugin.h
#include "gcc-plugin.h"	// Dynamic plugin gcc-plugin.h ==> vec.h
#include <stdio.h>      // stdio.h ==> vec.h
#include "vec.h"

#include "tree.h"       // tree.h ==> cgraph.h
#include "cgraph.h"

#include "tree-ssa-alias.h" // tree-ssa-alias.h ==> gimple.h
#include "basic-block.h"    // basic-block.h ==> gimple.h
#include "gimple-expr.h"    // gimple-expr.h ==> gimple.h
#include "gimple.h"

#include "gimple-ssa.h"
#include "tree-phinodes.h"
#include "ssa-iterators.h" //imm_use_iterator

extern tree get_ref_base_and_extent (tree, HOST_WIDE_INT *,HOST_WIDE_INT *, HOST_WIDE_INT *); //AH

/*------------------------------------------------------------------------------
 * STRONG DEPENDENCIES: END
 *----------------------------------------------------------------------------*/

#include "gimple-iterator.h" // needed for gimple_iterator
#include "tree-cfg.h" // needed for first_stmt
#include "tree-ssa-operands.h"  //PHI_ARG_DEF
#include "print-tree.h"

/*------------------------------------------------------------------------------
 * SOFT / NO DEPENDENCIES: START (Anshuman: No particular order discovered)
 *----------------------------------------------------------------------------*/
#include <cstdlib>		// If this is not the first header file, 
                        // we get POISONED error on using -std=c++0x 
                        //AN (Anshuman: didn't find it so)
#include "stdint.h"     //for uint64_t definition 
#include "coretypes.h"
#include "ggc.h"
#include "alloc-pool.h"
#include "params.h"
#include "string.h"
#include "config.h"
#include "stdlib.h"
#include "system.h"
#include "tm.h"
#include "diagnostic.h"
#include "gimple-pretty-print.h"
//AN #include "tree-flow.h" //AN no more in 5.2
#include "tree-pass.h"
#include "toplev.h"
#include "cfgloop.h"
#include <map>
#include <set>
#include <stack>
#include <list>
#include <vector>
#include <tr1/unordered_map>
#include <string>
#include <ctime>
#include "stor-layout.h" //KO  NEWADD
#include "context.h" //AN NEWADD required for gcc::context *g
#include "gimple-iterator.h" //AN NEWADD
//AN #include <boost/bimap.hpp>
/*------------------------------------------------------------------------------
 * SOFT / NO DEPENDENCIES: END
 *----------------------------------------------------------------------------*/

using namespace std;
using namespace std::tr1;
//using namespace boost;

#define RESULT(...) fprintf (dump_file, __VA_ARGS__)
//#define RESULT(...)

