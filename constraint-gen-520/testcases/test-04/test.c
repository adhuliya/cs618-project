// One Single Pointer and a Double Pointer
// Enumerating semantically meaningful operations using a double pointer and
// a direct pointer to int.
int main() {
    int *pi;    // pi = pointer-to int
    int **ppi;  // ppi = pointer-to pointer-to int

    ppi = &pi;          //YES

    ppi = &pi + 1;      //YES

    ppi = &pi - 1;      //YES

    pi = *ppi;          //YES
                        //YES 2 more statements are generated here in GIMPLE???
    *ppi = pi;          //YES

    return 0;
}

