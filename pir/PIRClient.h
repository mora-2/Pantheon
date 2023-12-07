#pragma once
#include "seal/seal.h"

using namespace seal;
using namespace std;

class PIRClient
{
public:
    /* Database params */
    uint32_t key_size; // in bits
    uint32_t obj_size;
    uint32_t pir_num_columns_per_obj;
    int NUM_COL = 32;

    /* Crypto params */
    std::unique_ptr<EncryptionParameters> parms;
    std::unique_ptr<SEALContext> context;
    std::unique_ptr<KeyGenerator> keygen;
    SecretKey secret_key;
    std::stringstream keys_ss; // relin_keys + galois_keys
    std::unique_ptr<BatchEncoder> batch_encoder;

    size_t row_size;
    std::unique_ptr<Encryptor> encryptor;
    std::unique_ptr<Evaluator> evaluator;
    std::unique_ptr<Decryptor> decryptor;

    /* one ciphertext */
    std::stringstream one_ct_ss;

    /* query */
    int desired_index;
    std::stringstream qss;

    /* Reconstruct */
    Plaintext result_pt;
    vector<uint64_t> result_mat;

public:
    PIRClient(uint32_t key_size, uint32_t obj_size);
    /* Crypto setup */
    void SetupCrypto(std::stringstream &parms_ss);
    //-----------> send key_ss

    /* SentOneCiphertext */
    void SetOneCiphertext(); // put ciphertext into one_ct_ss
    //-----------> send one_ct_ss

    /* QueryMake */
    void QueryMake(int desired_index); // save to qss
    //-----------> send qss

    /* Reconstruct */
    void Reconstruct(std::stringstream &ss);

    ~PIRClient();

private:
    void SetupDBParams(uint32_t key_size, uint32_t obj_size);
    void sha256(const char *str, int len, unsigned char *dest);
    vector<uint64_t> rotate_plain(std::vector<uint64_t> original, int index);
};