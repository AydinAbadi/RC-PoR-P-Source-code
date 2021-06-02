//

#include <iostream>
#include <math.h>
#include <string>
#include <stdio.h>
#include <vector>
#include <stdlib.h>
#include "cryptopp/cryptlib.h"
#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/secblock.h"
#include "gmp.h"
#include <gmpxx.h>
#include "Rand.h"
using namespace std;
using namespace CryptoPP;
typedef mpz_t bigint;

//===============================
string toBinary(int n){

  string res;
  while(n != 0) {
    res = (n % 2 == 0 ?"0":"1") + res;
    n /= 2;
  }
  return res;
}

//===============================
bigint* encode_file(bigint* file, int file_size, int pad_size){

  bigint* encoded_file;
  string str_file, str_index, str_diff, str_padded_file;
  int diff;
  encoded_file = (bigint*)malloc(file_size * sizeof(bigint));
  for(int i = 0; i < file_size; i++){
    //convert each file block into bitstring
    str_file = mpz_get_str (NULL, 2, file[i]);
    //convert integer i to binary string.
    str_index = toBinary(i);
    //pad the file with fixed size tail
    if(str_index.length() < pad_size){
      diff = pad_size - str_index.length();
      for(int i = 0; i < diff; i++){
        str_diff += '0';
      }
    }
    str_padded_file = str_file + str_diff + str_index;
    // convert bitstring to bigint.
    char* ar = new char[str_padded_file.length() + 1];
    strcpy(ar, str_padded_file.c_str());
    mpz_init_set_str(encoded_file[i], ar, 2);
    str_padded_file.clear();
    str_index.clear();
    str_file.clear();
    str_diff.clear();
  }
  return encoded_file;
}

//===============================
bool search(int* array, int size, int val){

  for (int i = 0; i < size; ++i){
    if (array[i] == val){
      return true;
    }
  }
  return false;
}

//===============================
int extract_tail(bigint encoded_file, int pad_size){

  int extracted_tail;
  string str_file, sub_str_file;
  str_file = mpz_get_str (NULL, 2, encoded_file);// convert the bigint to bitstring
  sub_str_file = str_file.substr(str_file.length() - pad_size, pad_size);// extract the tail
  // convert the tail (in bitstring) to an integer.
  char* char_;
  char_ = new char[sub_str_file.length() + 1];
  strcpy(char_, sub_str_file.c_str());
  char * pEnd;
  extracted_tail = strtoull (char_, &pEnd, 2);
  str_file.clear();
  sub_str_file.clear();
  return extracted_tail;
}

//===============================
// description: given values a and b, it returns hash(a||b)
bigint* hash_combined_values(bigint val_1, bigint val_2){
  string s_val_1, s_val_2, s_val_com;
  CryptoPP::SHA256 hash2;
  byte digest[CryptoPP::SHA256::DIGESTSIZE];
  bigint* res;
  res = (bigint*)malloc(1 * sizeof(bigint));
  s_val_1 = mpz_get_str(NULL, 10, val_1);
  s_val_2 = mpz_get_str(NULL, 10, val_2);
  s_val_com = s_val_1 + s_val_2;
  unsigned int nDataLen = s_val_com.length();
  hash2.CalculateDigest(digest, (byte*)s_val_com.c_str(), nDataLen);
  s_val_com.clear();
  s_val_1.clear();
  s_val_2.clear();
  mpz_init(res[0]);
  mpz_import(res[0], sizeof(digest), 1, sizeof(digest[0]), 0, 0, digest);
  return res;
}

//===============================
bigint** build_MT_tree(bigint* file, int file_size){

  CryptoPP::SHA256 hash2;
  byte digest[CryptoPP::SHA256::DIGESTSIZE];
  int number_of_levels = log2(file_size);// number of levels excluding leaf nodes level
  bigint** nodes;
  bigint* res_;
  nodes = (bigint**)malloc(number_of_levels * sizeof(bigint));// initiate a 2-D array
  int temp_size_1, j, temp_size_2;
  for (int  k = 0; k < number_of_levels; k++){
    temp_size_1 = file_size/(pow(2, k+1));//number of nodes in each level starting from one level up the leaf nodes
    nodes[k] = (mpz_t*)malloc(temp_size_1 * sizeof(mpz_t));// initiate each array
    j = 0;
    temp_size_2 = file_size/(pow(2, k));
    for(int i = 0; i < temp_size_2;){
      if(k == 0){
        res_ = hash_combined_values(file[i], file[i+1]);
        mpz_init_set(nodes[k][j], res_[0]);
        mpz_clear(res_[0]);
        j++;
        i += 2;
      }
      else{
        res_ = hash_combined_values(nodes[k-1][i], nodes[k-1][i+1]);
        mpz_init_set(nodes[k][j], res_[0]);
        mpz_clear(res_[0]);
        j++;
        i += 2;
      }
    }
  }
  return nodes;
}

//===============================
bool is_there_duplicated_elem(int* ar, int ar_size){

  int counter;
  int temp;
  for(int i = 0; i < ar_size; i++){
    temp = ar[i];
    counter = 0;
    for(int j = 0; j < ar_size; j++){
      if(ar[j] == temp){
        counter++;
      }
    }
    if (counter > 1){
      return true;
    }
  }
  return false;
}

//===============================
int* gen_chall(int number_of_chall, int bit_size_of_chall, int int_modulus){

    Random rd_;
    int* ar;
    ar = new int[number_of_chall];
    bigint* set, bigint_modulus;
    set = (bigint*)malloc(number_of_chall * sizeof(bigint));
    set = rd_.gen_randSet(number_of_chall, bit_size_of_chall);// generate a set of random bigint
    // put them in the range: [0,int_modulus-1]
    mpz_init(bigint_modulus);
    mpz_set_ui(bigint_modulus, int_modulus);
    for (int i = 0; i < number_of_chall; i++){
      mpz_mod(set[i], set[i], bigint_modulus);
      ar[i] = mpz_get_ui(set[i]);
      mpz_clear(set[i]);
    }
    bool duplicated_ = is_there_duplicated_elem(ar, number_of_chall);
    if(duplicated_){
      cout<<"\n\n\t\t*******************************************************"<<endl;
      cout<<"\n\n\t\tNOTE: The challange array contains duplicated values--Pick a new array"<<endl;
      cout<<"\n\n\t\t*******************************************************"<<endl;
    }
    return ar;
}

//===============================
int find_index(bigint* set, int set_size, bigint val,bool &res_){

  int res;
  for(int i = 0; i < set_size; i++){
    if (mpz_cmp(set[i], val) == 0){
      res_ = true;
      return i;// 0 means val exists in the set
    }
  }
  res_ = false;
  return 0;
}

//===============================
bigint*** gen_proof(int number_of_chall, int* challenge, bigint* file, int file_size, bigint** nodes){

  bigint*** proof;
  proof = (bigint***)malloc(number_of_chall * sizeof(bigint));
  int size_1 = log2(file_size) + 2; //number of elements in each proof (related to each challenge)
  int number_of_levels = log2(file_size) + 1;// number of levels in the tree including leaf nodes
  bigint* temp_hash;
  temp_hash = (mpz_t*)malloc(1 * sizeof(mpz_t));
  for(int i = 0; i < number_of_chall; i++){
    proof[i] = (bigint**)malloc(size_1 * sizeof(bigint));
    //go through different levels of the tree including leaf nodes
    int j = 0;
    for (int  k = 0; k < number_of_levels; k++){
      if(k == 0){
        if(challenge[i] % 2 == 0){ // if challenge[i] (or the index of challenged file block) is even
          proof[i][j] = (bigint*)malloc(2 * sizeof(bigint));
          mpz_init_set(proof[i][j][0], file[challenge[i]]); // insert leaf node file[challenge[i]] to the proof
          mpz_init_set_str(proof[i][j][1], "0", 10);
          j++;
          proof[i][j] = (bigint*)malloc(2 * sizeof(bigint));
          mpz_init_set(proof[i][j][0], file[challenge[i] + 1]); // insert the next leaf node file: [challenge[i]] to the proof
          mpz_init_set_str(proof[i][j][1], "0", 10);
          j++;
         // generate hash(file[challenge[i]] ||file[challenge[i]+1])
          temp_hash = hash_combined_values(file[challenge[i]],file[challenge[i] + 1]);
        }
        else{ // if challenge[i] is odd
          proof[i][j] = (bigint*)malloc(2 * sizeof(bigint));
          mpz_init_set(proof[i][j][0], file[challenge[i]-1]); // insert leaf node file[challenge[i]] to the proof
          mpz_init_set_str(proof[i][j][1], "0", 10);
          j++;
          proof[i][j] = (bigint*)malloc(2 * sizeof(bigint));
          mpz_init_set(proof[i][j][0], file[challenge[i]]); // insert the next leaf node file: [challenge[i]] to the proof
          mpz_init_set_str(proof[i][j][1], "0", 10);
          j++;
          temp_hash = hash_combined_values(file[challenge[i]-1], file[challenge[i]]);
        }
      }
      else{ // if k is not zero--   // find the index of temp_hash in the next level node
        int nonil = file_size/(pow(2, k));//nonil: number_of_nodes_inEach_level
        bool res_;
        int index = find_index(nodes[k-1], nonil, temp_hash[0], res_); // find the index of temp_hash in nodes[k-1]
        if(index % 2 == 0 && res_){
          if(index == 0 && k+1 == number_of_levels){
            proof[i][j] = (bigint*)malloc(2 * sizeof(bigint));
            mpz_init_set(proof[i][j][0], nodes[k-1][index]);
            mpz_init_set_str(proof[i][j][1], "0", 10);
          }
          else{
            proof[i][j] = (bigint*)malloc(2 * sizeof(bigint));
            mpz_init_set(proof[i][j][0], nodes[k-1][index+1]);
            mpz_init_set_str(proof[i][j][1], "0", 10);
            j++;
            temp_hash = hash_combined_values(nodes[k-1][index], nodes[k-1][index+1]);
          }
        }
        else if(index % 2 != 0 && res_){
          proof[i][j] = (bigint*)malloc(2 * sizeof(bigint));
          mpz_init_set(proof[i][j][0], nodes[k-1][index-1]);
          mpz_init_set_str(proof[i][j][1], "1", 10);
          j++;
          temp_hash = hash_combined_values(nodes[k-1][index-1], nodes[k-1][index]);
        }
      }
    }
  }
  mpz_clear(temp_hash[0]);
  return proof;
}

//===============================
vector<int> verify_proof(bigint*** proof, bigint root_node, int* challenge, int number_of_chall, int file_size, int pad_size){

  int size_1 = log2(file_size) + 1;
  int tail_1, tail_2;
  bool is_in, is_in_;
  vector<int> res_;
  vector<int> vec;
  bigint* temp_hash;
  bigint one;
  mpz_init_set_str(one, "1", 10);
  temp_hash = (mpz_t*)malloc(1 * sizeof(mpz_t));
  for(int i = 0; i < number_of_chall; i++){
    for (int  j = 0; j < size_1; j++){
      if(j == 0){
        // extract the tail of the two leaf nodes
        tail_1 = extract_tail(proof[i][j][0], pad_size);
        tail_2 = extract_tail(proof[i][j+1][0], pad_size);
        // check if the tail equals the related challenge.
        is_in = search(challenge, number_of_chall, tail_1);
        is_in_ = search(challenge, number_of_chall, tail_2);
        // check if (1) either proof[i][j][0] or  proof[i][j+1][0] is the challenged block,
        // and (2) there is no duplication of proof.
        if(((is_in || is_in_) == true) && (find(vec.begin(), vec.end(), challenge[i]) == vec.end())){
          temp_hash = hash_combined_values(proof[i][j][0], proof[i][j+1][0]);
          vec.push_back(challenge[i]);
        }
        else{
          res_.push_back(i);// store the index of rejected proof
          break; //exit the inner loop.
        }
        j++;
      }
      else{ // if j!=0
        if(mpz_cmp(proof[i][j][1], one) == 0){
          temp_hash = hash_combined_values(proof[i][j][0], temp_hash[0]);
        }
        else{// if mpz_cmp(proof[i][j][1], one) != 0) or when mpz_cmp(proof[i][j][1], zero) == 0
          temp_hash = hash_combined_values(temp_hash[0], proof[i][j][0]);
        }
      }
      if(j+1 == size_1){
        if(mpz_cmp(temp_hash[0], root_node)!=0){
          res_.push_back(i); // store the index of rejected proof
        }
      }
    }
  }
  mpz_clear(temp_hash[0]);
  return res_;
}

//===============================
int main() {

    bigint* file;
    bigint test_,root_;
    bigint** nodes;
    int file_size = 67108864;
    string binary_fileSize = toBinary(file_size);
    int pad_size = binary_fileSize.length()+1;
    int block_bit_size = 128;
    int number_of_levels = log2(file_size);
    int number_of_chall = 20;
    int bit_size_of_chall = 80;
    int int_modulus = file_size;
    file = (bigint*)malloc(file_size * sizeof(bigint));
    Random rd_;
    cout<<"\n 1- Genenerating a random file"<<endl;
    file = rd_.gen_randSet(file_size, block_bit_size);
    //cout<<"\n file[0]:"<< file[0]<<endl;

    // mpz_init_set_str(file[0], "5", 10);
    // mpz_init_set_str(file[1], "6", 10);
    // mpz_init_set_str(file[2], "7", 10);
    // mpz_init_set_str(file[3], "8", 10);
    // mpz_init_set_str(file[4], "9", 10);
    // mpz_init_set_str(file[5], "10", 10);
    // mpz_init_set_str(file[6], "11", 10);
    // mpz_init_set_str(file[7], "12", 10);
    //1- encode the file
    //cout<<"\n 1:"<<endl;

    cout<<"\n 2- Encoding the file"<<endl;
    bigint* encoded_file = encode_file(file, file_size, pad_size);
    //2- build a Merkle tree on the encoded file.
    cout<<"\n 3- Building a tree on the file"<<endl;
    nodes = build_MT_tree(encoded_file, file_size);
    //cout<<"\n 3:"<<endl;
    //3- extract the root
    mpz_init_set(root_, nodes[number_of_levels-1][0]);
    // 4- generate challenges
    cout<<"\n 4- Generating Challenges"<<endl;
    int* chall = gen_chall(number_of_chall, bit_size_of_chall, int_modulus);
    for (int i = 0; i< number_of_chall; i++){
      cout<<"\n challneged block indices: " <<chall[i]<<endl;
    }
    // 5- generate proofs
    cout<<"\n 5- Generating proofs"<<endl;
    bigint*** proof_ = gen_proof(number_of_chall, chall, encoded_file, file_size, nodes);
    //6- verify valid proofs
    cout<<"\n 6- Verifying proofs"<<endl;
    vector<int> vec_ = verify_proof(proof_, root_, chall, number_of_chall, file_size, pad_size);
    string status;
    if(vec_.size() == 0){
      status = "All proofs are VALID";
    }
    else{
      status = "Some proofs are INVALID";
    }
    cout<<"\n\n------------"<<endl;
    cout<< "\n Status: "<<status<<endl;
    if (status == "Some proofs are INVALID"){

      for(int i = 0; i < vec_.size(); i++){
        cout<<"\n Rejected proof index:"<<vec_[i]<<endl;
      }
    }
        cout<<"\n\n------------"<<endl;
    //7- for test only- verify invalid proofs
    // cout<<"\n\n------For test only------"<<endl;
    // bigint one;
    // mpz_init_set_str(one, "4",10);
    // mpz_set(proof_[1][0][0],one);
    // vector<int> vec_1 = verify_proof(proof_, root_, chall, number_of_chall, file_size, pad_size);
    // cout<<"\n Number of invalid proofs:"<<vec_1.size()<<endl;
    // for(int i=0;i<vec_1.size(); i++){
    //   cout<<"\n rejected proof index:"<<vec_1[i]<<endl;
    //   //cout<<"\n rejected proof index:"<<chall[vec_1[i]]<<endl;
    // }

    return 0;
}
