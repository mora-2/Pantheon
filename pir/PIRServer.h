#pragma once
#include <cstdint>
#include "seal/seal.h"
#include "config.h"

using namespace seal;
using namespace std;

class PIRServer
{
public:
    /* database params */
    uint64_t number_of_items;
    uint64_t number_of_items_total;
    uint32_t key_size; // in bits
    uint32_t obj_size;
    uint32_t num_multimap;
    int NUM_ROW;
    int NUM_COL;

    vector<vector<uint32_t>> multikey_db;
    unique_ptr<vector<uint64_t>> keyword_freq_ptr;
    vector<vector<Plaintext>> db;
    vector<vector<vector<Plaintext>>> multimap_db;
    seal::parms_id_type compact_pid; // for one ctx used in db encode

    /* PIR params */
    uint32_t pir_num_obj;
    uint32_t pir_obj_size;
    uint32_t pir_key_size; //  in bits
    uint32_t pir_num_query_ciphertext;
    uint32_t pir_num_columns_per_obj;
    uint32_t pir_plain_bit_count;
    uint32_t pir_db_rows;

    /* Setup DB */
    struct ParetoParams
    {
        double alpha;
        size_t max_value;
        size_t num_samples;
        ParetoParams(double alpha, size_t max_value, size_t num_samples) : alpha(alpha), max_value(max_value), num_samples(num_samples) {}
    };
    vector<vector<uint64_t>> pir_db; // 64 bit placeholder for 16 bit plaintext coefficients
    vector<vector<vector<uint64_t>>> multimap_pir_db;
    vector<Plaintext> pir_encoded_db;
    vector<vector<Plaintext>> multimap_pir_encoded_db;

    /* Crypto params */
    std::unique_ptr<EncryptionParameters> parms;
    std::stringstream parms_ss;
    std::unique_ptr<SEALContext> context;
    GaloisKeys galois_keys;
    RelinKeys relin_keys;
    std::unique_ptr<Evaluator> evaluator;
    std::unique_ptr<BatchEncoder> batch_encoder;

    /* Memory pool */
    vector<MemoryPoolHandle> column_pools;

    /* OneCiphertext */
    Ciphertext one_ct; // receive from client

    /* QueryExpand */
    vector<Plaintext> masks;
    Ciphertext server_query_ct;
    vector<Ciphertext> expanded_query;

    /* Process1 */
    vector<Ciphertext> row_result;
    vector<vector<Ciphertext>> multimap_row_result;

    /* Process2 */
    vector<Ciphertext> pir_results;
    vector<vector<Ciphertext>> multimap_pir_results;

    /* datastream */
    std::stringstream ss;

public:
    static const uint32_t INVALID_INDEX;

private:
    static const size_t INVALID_KEY;

    int NUM_COL_THREAD; // sub thread
    int NUM_ROW_THREAD; // main thread
    int NUM_PIR_THREAD;
    int TOTAL_MACHINE_THREAD;
    int NUM_EXPANSION_THREAD;
    int NUM_EXPONENT_THREAD;

    struct ExpandQueryStructure
    {
        int id;
        size_t db_i;
        PIRServer *server;
        ExpandQueryStructure(int id, PIRServer *server) : id(id), db_i(0), server(server) {}
        ExpandQueryStructure(int id, size_t db_i, PIRServer *server) : id(id), db_i(db_i), server(server) {}
    };
    struct ProcessRowStructure
    {
        int id;
        size_t db_i;
        PIRServer *server;
        ProcessRowStructure(int id, PIRServer *server) : id(id), db_i(0), server(server) {}
        ProcessRowStructure(int id, size_t db_i, PIRServer *server) : id(id), db_i(db_i), server(server) {}
    };
    struct ProcessColStructure
    {
        column_thread_arg col_arg;
        size_t db_i;
        PIRServer *server;
        ProcessColStructure(column_thread_arg col_arg, PIRServer *server) : col_arg(col_arg), db_i(0), server(server) {}
        ProcessColStructure(column_thread_arg col_arg, size_t db_i, PIRServer *server) : col_arg(col_arg), db_i(db_i), server(server) {}
    };
    struct MultiplyColStructure
    {
        mult_thread_arg mult_arg;
        size_t db_i;
        PIRServer *server;
        MultiplyColStructure(mult_thread_arg mult_arg, PIRServer *server) : mult_arg(mult_arg), db_i(0), server(server) {}
        MultiplyColStructure(mult_thread_arg mult_arg, size_t db_i, PIRServer *server) : mult_arg(mult_arg), db_i(db_i), server(server) {}
    };
    struct ProcessPIRStructure
    {
        int my_id;
        size_t db_i;
        PIRServer *server;
        ProcessPIRStructure(int my_id, PIRServer *server) : my_id(my_id), db_i(0), server(server) {}
        ProcessPIRStructure(int my_id, size_t db_i, PIRServer *server) : my_id(my_id), db_i(db_i), server(server) {}
    };

public:
    PIRServer(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size);
    PIRServer(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size, uint32_t num_multimap);
    PIRServer(ParetoParams pareto, uint32_t key_size, uint32_t obj_size);
    /* Crypto setup */
    void SetupCryptoParams();
    //-----------> send parms_ss
    void SetupKeys(std::stringstream &keys_ss /* relin_keys + galois_keys */);

    /* Receive OneCiphertext */
    void RecOneCiphertext(std::stringstream &one_ct_ss);

    /* Setup DB */
    void SetupDB();
    void SetupDB(vector<string> &keydb, vector<string> &elems);

    /* QueryExpand */
    void QueryExpand(std::stringstream &qss);

    /* Process1  */
    void Process1();

    /* Process2 */
    void Process2();
    //-----------> send ss

    ~PIRServer() = default;

private:
    void SetupDBParams(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size);
    void SetupDBParams(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size, uint32_t num_multimap);
    void SetupMemPool();
    void SetupThreadParams();
    void SetupPIRParams();
    void populate_db();
    void populate_multimap_db();
    void pareto_multimap_db();
    void populate_db(vector<string> &keydb);
    std::pair<unique_ptr<vector<uint64_t>>, uint64_t> generateDiscretePareto(double alpha, uint64_t maxVal, uint64_t numSamples);
    void sha256(const char *str, int len, unsigned char *dest);
    void set_pir_db(std::vector<std::vector<uint64_t>> db);
    void pir_encode_db(std::vector<std::vector<uint64_t>> db);
    void set_pir_multimap_db(std::vector<std::vector<uint64_t>> db, size_t db_i);
    void pir_encode_multimap_db(std::vector<std::vector<uint64_t>> db, size_t db_i);
    static void *expand_query(void *arg);
    static void *process_rows(void *arg);
    static void *process_columns(void *arg);
    static void *multiply_columns(void *arg);
    static void *process_pir(void *arg);
    static Ciphertext get_sum(vector<Ciphertext> &query, uint32_t start, uint32_t end, PIRServer *server);
    static Ciphertext get_sum(vector<Ciphertext> &query, uint32_t start, uint32_t end, PIRServer *server, size_t db_i);
    static uint32_t get_next_power_of_two(uint32_t number);
    static uint32_t get_number_of_bits(uint64_t number);

public:
    void DBIndexSearch(uint32_t desired_index, vector<uint32_t> &db_index);
};