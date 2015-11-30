// This program enumerates the semantically meaningful statements possible using 
// a single pointer variable (pointer to int). 
int* func (int *piFormal);
int main() {
    int i = 17;
    int *pi;

    pi = &i;        //YES

    i = *pi;        //NO

    *pi = 19;       //NO

    pi = pi + 1;    //YES

    pi = pi - 1;    //YES

    pi++;           //YES

    pi--;           //YES

    pi = 0;         //YES Assigning NULL

    pi = 17;        //NO - But allowed!

    func (pi);

    return 0;
}

int* func (int *piFormal) {
    return piFormal;
}
