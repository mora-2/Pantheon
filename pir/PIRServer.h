#pragma once
#include <cstdint>
#include "seal/seal.h"

using namespace seal;
using namespace std;

class PIRServer
{
public:
    /* database params */
    uint64_t number_of_items;
    uint32_t key_size; // in bits
    uint32_t obj_size;
    static int NUM_ROW;
    static int NUM_COL;

    static vector<vector<Plaintext>> db;
    seal::parms_id_type compact_pid; // for one ctx used in db encode

    /* PIR params */
    uint32_t pir_num_obj;
    uint32_t pir_obj_size;
    uint32_t pir_key_size; //  in bits
    static uint32_t pir_num_query_ciphertext;
    static uint32_t pir_num_columns_per_obj;
    uint32_t pir_plain_bit_count;
    uint32_t pir_db_rows;

    /* Setup DB */
    vector<vector<uint64_t>> pir_db; // 64 bit placeholder for 16 bit plaintext coefficients
    static vector<Plaintext> pir_encoded_db;

    /* Crypto params */
    std::unique_ptr<EncryptionParameters> parms;
    std::stringstream parms_ss;
    static std::unique_ptr<SEALContext> context;
    static GaloisKeys galois_keys;
    static RelinKeys relin_keys;
    static std::unique_ptr<Evaluator> evaluator;
    std::unique_ptr<BatchEncoder> batch_encoder;

    /* Memory pool */
    static vector<MemoryPoolHandle> column_pools;

    /* OneCiphertext */
    static std::shared_ptr<Ciphertext> one_ct; // receive from client

    /* QueryExpand */
    static vector<Plaintext> masks;
    static Ciphertext server_query_ct;
    static vector<Ciphertext> expanded_query;

    /* Process1 */
    static vector<Ciphertext> row_result;

    /* Process2 */
    static vector<Ciphertext> pir_results;

    /* datastream */
    std::stringstream ss;

private:
    static int NUM_COL_THREAD; // sub thread
    static int NUM_ROW_THREAD; // main thread
    static int NUM_PIR_THREAD;
    static int TOTAL_MACHINE_THREAD;
    static int NUM_EXPANSION_THREAD;
    static int NUM_EXPONENT_THREAD;

public:
    PIRServer(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size);
    /* Crypto setup */
    void SetupCryptoParams();
    //-----------> send parms_ss
    void SetupKeys(std::stringstream &keys_ss /* relin_keys + galois_keys */);

    /* Receive OneCiphertext */
    void RecOneCiphertext(std::stringstream &one_ct_ss);

    /* Setup DB */
    void SetupDB();

    /* QueryExpand */
    void QueryExpand(std::stringstream &qss);

    /* Process1  */
    void Process1();

    /* Process2 */
    void Process2();
    //-----------> send ss

    ~PIRServer();

private:
    void SetupDBParams(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size);
    void SetupMemPool();
    void SetupThreadParams();
    void SetupPIRParams();
    void populate_db();
    void sha256(const char *str, int len, unsigned char *dest);
    void set_pir_db(std::vector<std::vector<uint64_t>> db);
    void pir_encode_db(std::vector<std::vector<uint64_t>> db);
    static void *expand_query(void *arg);
    static void *process_rows(void *arg);
    static void *process_columns(void *arg);
    static void *multiply_columns(void *arg);
    static void *process_pir(void *arg);
    static Ciphertext get_sum(vector<Ciphertext> &query, uint32_t start, uint32_t end);
    static uint32_t get_next_power_of_two(uint32_t number);
    static uint32_t get_number_of_bits(uint64_t number);
};