// Two double pointers
// ppi = pointer-to pointer-to int
int main () {
    int **ppiA;
    int **ppiB;
    int i;

    ppiA = ppiB;        //YES

    *ppiA = *ppiB;      //YES = two gimple statements (using a temporary)

    **ppiA = **ppiB;    //YES = four gimple statements

    i = ppiA - ppiB;    //NO

    return 0;
}
