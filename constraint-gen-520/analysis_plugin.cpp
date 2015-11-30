
/************************
 * @author Vini Kanvar
************************/

#include "analysis_plugin.hh"

// class parser's object PROGRAM is made global
parser program;

static unsigned int
heap_analysis ()
{
	// Run this analysis only in LTO mode
	if (!in_lto_p)
		return 0;

    fprintf(dump_file, "\ncs618heap: STARTED.\n");
    std::cerr<<"\ncs618heap: STARTED.\n"; //AN NEWADD

	program.initialization ();
    std::cerr << "Part 1 Done \n" ;
    program.preprocess_control_flow_graph ();
    std::cerr << "Part 2 Done \n" ;
	program.print_parsed_data ();
	program.print_original_cfg();
	program.delete_block_aux ();

	RESULT ("\n\n");
    fprintf(dump_file, "\ncs618heap: ENDED.\n"); //AN NEWADD
    std::cerr<<"\ncs618heap: ENDED.\n"; //AN NEWADD

	return 0;
}


