#include <iostream>
#include "gmp.h"

using namespace std;

int main(){
#if WOOPING
    mpz_t ampz;
    mpz_init(ampz);
    mpz_set_str(ampz, "99837459873498753989873245938745928740598273405928734502983745", 10); 
    mp_limb_t wv = mpz_get_wv(ampz);
    mpz_check_woop(ampz);
    cout << wv << endl;
#endif
}
