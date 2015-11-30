// One double pointer.
// Enumerating semantically meaningful operations with one double pointer.
int main() {
    int **ppi;  // ppi = pointer-to pointer-to int

    ppi++;              //YES

    ppi--;              //YES

    ppi = ppi + 1;              //YES

    ppi = ppi - 1;              //YES

    **ppi = 10;             //YES - partially only when "D.2354_6 = *ppi_5"

    *ppi = 0;               //YES

    *ppi = 17;              //NO - However semantically unmeaningful

    return 0;
}
