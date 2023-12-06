#pragma once
#include <cstdint>

class PIRServer
{
public:
    /* database params */
    uint64_t number_of_items;
    uint32_t key_size; // in bits
    uint32_t obj_size;
    int NUM_ROW = 32;
    int NUM_COL = 8;

    std::shared_ptr<vector<vector<Plaintext>>> db;
    seal::parms_id_type compact_pid; // for one ctx used in db encode

    /* PIR params */
    uint32_t pir_num_obj;
    uint32_t pir_obj_size;
    uint32_t pir_key_size; //  in bits
    uint32_t pir_num_query_ciphertext;
    uint32_t pir_num_columns_per_obj;
    uint32_t pir_plain_bit_count;
    uint32_t pir_db_rows;

    vector<Plaintext> pir_encoded_db;

    /* Crypto params */
    std::unique_ptr<EncryptionParameters> parms;
    std::unique_ptr<SEALContext> context;
    std::unique_ptr<KeyGenerator> keygen;
    SecretKey secret_key; // retain 
    GaloisKeys galois_keys;
    RelinKeys relin_keys;
    std::unique_ptr<Evaluator> evaluator;
    std::unique_ptr<BatchEncoder> batch_encoder;

    /* Memory pool */
    std::shared_ptr<MemoryPoolHandle[]> column_pools;

    /* QueryExpand params */
    vector<Plaintext> masks;
    std::unique_ptr<pthread_t[]> query_expansion_thread;
    std::unique_ptr<int[]> expansion_thread_id;

    /* Process1 */
    std::unique_ptr<pthread_t[]> row_process_thread;
    std::unique_ptr<int[]> row_thread_id;

    std::unique_ptr<pthread_t[]> col_process_thread;

    /* Process2 */
    std::unique_ptr<pthread_t[]> pir_thread;
    std::unique_ptr<int[]> pir_thread_id;

    /* Ciphertexts */
    std::shared_ptr<Ciphertext[]> expanded_query;
    std::shared_ptr<Ciphertext[]> row_result;
    std::shared_ptr<Ciphertext> one_ct;
    std::shared_ptr<Ciphertext> server_query_ct;
    std::shared_ptr<Ciphertext[]> column_results;
    std::shared_ptr<Ciphertext[]> pir_results;

    /* datastream */
    std::stringstream ss, qss;

private:
    int NUM_COL_THREAD; // sub thread
    int NUM_ROW_THREAD; // main thread
    int NUM_PIR_THREAD;
    int TOTAL_MACHINE_THREAD;
    int NUM_EXPANSION_THREAD;
    int NUM_EXPONENT_THREAD;

public:
    PIRServer(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size);

    ~PIRServer();

private:
    void SetupDBParams(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size);
    void SetupThreadParams();
    void SetupPIRParams();
    void SetupCryptoParams();
};