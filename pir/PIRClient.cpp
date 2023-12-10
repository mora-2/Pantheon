#include "PIRClient.h"
#include "globals.h"
#include <set>
#include <openssl/sha.h>
#include "utils.h"

PIRClient::PIRClient(uint32_t key_size, uint32_t obj_size)
{
    this->SetupDBParams(key_size, obj_size);
}

void PIRClient::SetupCrypto(std::stringstream &parms_ss)
{
    this->parms = std::make_unique<EncryptionParameters>();
    this->parms->load(parms_ss);

    this->context = std::make_unique<SEALContext>(*parms);

    this->keygen = std::make_unique<KeyGenerator>(*context);
    this->secret_key = keygen->secret_key();

    this->keygen->create_relin_keys().save(this->keys_ss);
    GaloisKeys galois_keys;
    set<int> rotation_steps;
    rotation_steps.insert(0);
    for (int i = N / (2 * NUM_COL); i < N / 2; i *= 2)
    {
        rotation_steps.insert(i);
    }

    for (int i = 1; i < (pir_num_columns_per_obj / 2); i *= 2)
    {
        rotation_steps.insert(-i);
    }
    keygen->create_galois_keys(vector<int>(rotation_steps.begin(), rotation_steps.end()), galois_keys);
    galois_keys.save(keys_ss);

    this->batch_encoder = std::make_unique<BatchEncoder>(*context);
    this->row_size = batch_encoder->slot_count() / 2;

    this->encryptor = std::make_unique<Encryptor>(*context, this->secret_key);
    this->evaluator = std::make_unique<Evaluator>(*context);
    this->decryptor = std::make_unique<Decryptor>(*context, secret_key);
}

void PIRClient::SetupCrypto(std::string &load_file_dir)
{
    string loaded_data = loadFromBinaryFile(load_file_dir + "/crypto_params");
    std::stringstream ss(loaded_data);

    this->parms = std::make_unique<EncryptionParameters>();
    this->parms->load(ss);
    this->context = std::make_unique<SEALContext>(*parms);

    loaded_data = loadFromBinaryFile(load_file_dir + "/crypto_secretkey");
    ss.str(loaded_data);
    this->secret_key.load(*context, ss);

    this->batch_encoder = std::make_unique<BatchEncoder>(*context);
    this->row_size = batch_encoder->slot_count() / 2;
    this->encryptor = std::make_unique<Encryptor>(*context, this->secret_key);
    this->evaluator = std::make_unique<Evaluator>(*context);
    this->decryptor = std::make_unique<Decryptor>(*context, secret_key);
}

void PIRClient::SetOneCiphertext()
{
    vector<uint64_t> temp_mat;
    Plaintext temp_pt;

    vector<uint64_t> one_mat;
    for (int i = 0; i < N; i++)
    {
        one_mat.push_back(1);
    }
    Plaintext one_pt;
    Ciphertext one_ct;
    batch_encoder->encode(one_mat, one_pt);

    encryptor->encrypt_symmetric(one_pt, one_ct);

    for (int k = 0; k < MOD_SWITCH_COUNT; k++)
    {
        evaluator->mod_switch_to_next_inplace(one_ct);
    }
    one_ct.save(this->one_ct_ss);
}

void PIRClient::QueryMake(int desired_index)
{
    this->desired_index = desired_index;
    vector<uint64_t> client_query_mat(N, 0ULL);

    int val = desired_index + 1;
    const char str[] = {val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF, 0};

    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256(str, 4, hash);

    for (int i = 0; i < NUM_COL; i++)
    {
        for (int j = i * (N / (NUM_COL * 2)); j < ((i + 1) * (N / (NUM_COL * 2))); j++)
        {
            client_query_mat[j] = (uint64_t(hash[4 * i]) << 8) + hash[4 * i + 1];
            ;
            client_query_mat[j + (N / 2)] = (uint64_t(hash[4 * i + 2]) << 8) + hash[4 * i + 3];
            ;
        }
    }

    Plaintext client_query_pt, result_pt;

    batch_encoder->encode(client_query_mat, client_query_pt);
    Serializable<Ciphertext> ser_query = encryptor->encrypt_symmetric(client_query_pt);
    ser_query.save(qss); // save query ciphertext

    // printf("query size (Byte): %lu\n", qss.str().size());
}

void PIRClient::QueryMake(string &desired_key)
{
    this->desired_key = desired_key;
    vector<uint64_t> client_query_mat(N, 0ULL);

    char str[NUM_COL * 4];
    int j = 0;
    for (j; j < desired_key.size(); j++)
    {
        str[j] = desired_key[j];
    }
    for (j; j < 4 * NUM_COL; j++)
    {
        str[j] = 0;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256(str, 4 * NUM_COL, hash);

    for (int i = 0; i < NUM_COL; i++)
    {
        for (int j = i * (N / (NUM_COL * 2)); j < ((i + 1) * (N / (NUM_COL * 2))); j++)
        {
            client_query_mat[j] = (uint64_t(hash[4 * i]) << 8) + hash[4 * i + 1];
            ;
            client_query_mat[j + (N / 2)] = (uint64_t(hash[4 * i + 2]) << 8) + hash[4 * i + 3];
            ;
        }
    }

    Plaintext client_query_pt, result_pt;

    batch_encoder->encode(client_query_mat, client_query_pt);
    Serializable<Ciphertext> ser_query = encryptor->encrypt_symmetric(client_query_pt);
    ser_query.save(qss); // save query ciphertext

    // printf("query size (Byte): %lu\n", qss.str().size());
}

vector<uint64_t> PIRClient::Reconstruct(std::stringstream &ss)
{
    Ciphertext final_result;
    final_result.load(*context, ss);

    // cout << "Result noise budget " << decryptor->invariant_noise_budget(final_result) << endl;

    decryptor->decrypt(final_result, result_pt);
    batch_encoder->decode(result_pt, result_mat);

    vector<uint64_t> decoded_response;
    decoded_response = rotate_plain(result_mat, desired_index % row_size);
    return decoded_response;
}

string PIRClient::ReconstructStr(std::stringstream &ss)
{
    Ciphertext final_result;
    final_result.load(*context, ss);

    // cout << "Result noise budget " << decryptor->invariant_noise_budget(final_result) << endl;

    decryptor->decrypt(final_result, result_pt);
    batch_encoder->decode(result_pt, result_mat);

    return this->getresult();
}

void PIRClient::SetupDBParams(uint32_t key_size, uint32_t obj_size)
{
    this->key_size = key_size;
    this->obj_size = obj_size;
    this->NUM_COL = (int)ceil(key_size / (2.0 * PLAIN_BIT));
    this->pir_num_columns_per_obj = 2 * (ceil(((obj_size / 2) * 8) / (float)(PLAIN_BIT)));
}

void PIRClient::sha256(const char *str, int len, unsigned char *dest)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, len);
    SHA256_Final(dest, &sha256);
}

vector<uint64_t> PIRClient::rotate_plain(std::vector<uint64_t> original, int index)
{
    int sz = original.size();
    int row_count = sz / 2;
    std::vector<uint64_t> result(sz);
    for (int i = 0; i < row_count; i++)
    {
        result[i] = original[(index + i) % row_count];
        result[row_count + i] = original[row_count + ((index + i) % row_count)];
    }

    return result;
}

string PIRClient::getresult()
{
    string res;
    if (result_mat[result_mat.size() - 1] != 0 && result_mat[0] != 0)
    {
        int i = 0;
        for (i; i < row_size; i++)
        {
            if (result_mat[i] == 0)
                break;
        }
        int j = i;
        int k = 0;
        for (i; i < result_mat.size() + j; i++)
        {
            if (result_mat[i] != 0)
            {
                if (result_mat[i] < 256)
                {
                    res = res + static_cast<char>(result_mat[i]);
                    break;
                }
                res = res + static_cast<char>(result_mat[i] / 256);
                res = res + static_cast<char>(result_mat[i] % 256);
                k++;
            }
        }
    }
    else
    {
        int k = 0;
        for (int i = 0; i < result_mat.size(); i++)
        {
            if (result_mat[i] != 0)
            {
                if (result_mat[i] < 256)
                {
                    res = res + static_cast<char>(result_mat[i]);
                    break;
                }
                res = res + static_cast<char>(result_mat[i] / 256);
                res = res + static_cast<char>(result_mat[i] % 256);
                k++;
            }
        }
    }
    return res;
}
