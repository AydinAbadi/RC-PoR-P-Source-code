//
//  main.cpp
//  test
//
//  Created by Aydin Abadi on 27/05/2021.
//

#include <iostream>
#include "gmp.h"
#include <gmpxx.h>
#include <string>
#include "cryptopp/cryptlib.h"
#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/secblock.h"
#include <stdio.h>
#include <stdlib.h>
using namespace std;


//#include <cryptopp/sha.h>
using namespace CryptoPP;
//using namespace CryptoPP;


int main() {
    
    mpz_t pr_val;
    mpz_init(pr_val);
    // insert code here...
    std::cout << "x-Big test!\n";
    CryptoPP::SHA512 hash2;
    ////////////
    byte digest[SHA512::DIGESTSIZE];
    //

    
 
    string s_val;
    unsigned int nDataLen = s_val.length();
    hash2.CalculateDigest(digest, (byte*)s_val.c_str(), nDataLen);
    mpz_import(pr_val, sizeof(digest), 1, sizeof(digest[0]), 0, 0, digest);
    cout<<pr_val<<endl;
    
    //
    //hash2.CalculateDigest(digest, (byte*)s_val.c_str(), 4);
    return 0;
}
