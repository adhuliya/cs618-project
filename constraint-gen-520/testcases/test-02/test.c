// Two pointer to integers.
// All semantically meaningful opertions possible with them.
// i,iA,iB = integer variables (A, B,... suffix used to differentiate only)
// pi, piA, piB = pointer to integer (A, B,... suffix used to differentiate only)
int main() {
    // int i = 17;
    // int ii = 19;
    int *piA, *piB;
    int i;

    piA = piB;      //YES copy pointers

    *piA = *piB;    //NO transfer int values

    i = piA - piB;  //NO difference of pointers

    // i = piA + piB;   // not allowed in C

    // Swap two pointes using xor : not allowed in C use (uintptr_t) cast.
    // piA = piA ^ piB;
    // piB = piA ^ piB;
    // piA = piA ^ piB;

    return 0;
}
