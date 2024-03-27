#include "PIRServer.h"
#include "globals.h"
#include <cmath>
#include <set>
#include <openssl/sha.h>
#include "config.h"
#include "utils.h"
#include <cassert>
#include <fstream>

const size_t PIRServer::INVALID_KEY = 0;
const uint32_t PIRServer::INVALID_INDEX = -1;

PIRServer::PIRServer(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size)
{
    this->keyword_freq_ptr = nullptr;
    this->num_multimap = 1;
    this->number_of_items_total = number_of_items;
    this->SetupDBParams(number_of_items, key_size, obj_size);
    this->SetupMemPool();
    this->SetupPIRParams();
    this->SetupThreadParams();
}

PIRServer::PIRServer(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size, uint32_t num_multimap)
{
    this->keyword_freq_ptr = nullptr;
    this->number_of_items_total = number_of_items * num_multimap;
    this->SetupDBParams(number_of_items, key_size, obj_size, num_multimap);
    this->SetupMemPool();
    this->SetupPIRParams();
    this->SetupThreadParams();
}

PIRServer::PIRServer(ParetoParams pareto, uint32_t key_size, uint32_t obj_size)
{
    auto samples_pair = this->generateDiscretePareto(pareto.alpha, pareto.max_value, pareto.num_samples);
    this->number_of_items_total = samples_pair.second; // total samples
    this->keyword_freq_ptr = std::move(samples_pair.first);
    assert(keyword_freq_ptr->size() <= UINT32_MAX); // num of keyword limited up to 2^32

    uint64_t num_multimap = *std::max_element(keyword_freq_ptr->begin(), keyword_freq_ptr->end()); // max frequency
    uint64_t number_of_items = ceil(number_of_items_total / (double)num_multimap);
    this->SetupDBParams(number_of_items, key_size, obj_size, num_multimap);
    this->SetupMemPool();
    this->SetupPIRParams();
    this->SetupThreadParams();
}

void PIRServer::SetupCryptoParams()
{
    this->parms = std::make_unique<EncryptionParameters>(scheme_type::bfv);
    parms->set_poly_modulus_degree(N);
    parms->set_coeff_modulus(CoeffModulus::Create(N, CT_PRIMES));
    parms->set_plain_modulus(PLAIN_MODULUS);
    /* save into stream */
    this->parms->save(this->parms_ss);

    this->context = std::make_unique<SEALContext>(*parms);

    this->evaluator = std::make_unique<Evaluator>(*context);
    this->batch_encoder = std::make_unique<BatchEncoder>(*context);
}

void PIRServer::SetupKeys(std::stringstream &keys_ss)
{
    this->relin_keys.load(*context, keys_ss);
    this->galois_keys.load(*context, keys_ss);
}

void PIRServer::RecOneCiphertext(std::stringstream &one_ct_ss)
{
    this->one_ct.load(*context, one_ct_ss);
    this->compact_pid = one_ct.parms_id();
}

void PIRServer::SetupDB()
{

    if (this->num_multimap == 0)
    { // is multiple mapping
        this->pir_db.resize(0);
        populate_db();
        for (int i = 0; i < pir_num_obj; i++)
        {
            vector<uint64_t> v;
            for (int j = 0; j < (pir_obj_size / 2); j++)
            { // 2 bytes each plaintxt slot
                v.push_back(rand() % PLAIN_MODULUS);
            }
            pir_db.push_back(v);
        }
        set_pir_db(pir_db);
        // cout << "DB population complete!" << endl;
    }
    else
    {
        this->multimap_pir_db.resize(this->num_multimap);
        for (vector<vector<uint64_t>> &e : this->multimap_pir_db)
        {
            e.resize(0);
        }
        if (this->keyword_freq_ptr == nullptr)
        { // is db sampled from Pareto distribution
            this->populate_multimap_db();
        }
        else
        { // sample from Pareto, multimap
            this->pareto_multimap_db();
        }

        this->multimap_pir_encoded_db.resize(num_multimap);
        for (size_t db_i = 0; db_i < this->num_multimap; db_i++)
        {
            for (int i = 0; i < pir_num_obj; i++)
            {
                vector<uint64_t> v;
                for (int j = 0; j < (pir_obj_size / 2); j++)
                { // 2 bytes each plaintxt slot
                    v.push_back(rand() % PLAIN_MODULUS);
                }
                multimap_pir_db[db_i].push_back(v);
            }
            set_pir_multimap_db(multimap_pir_db[db_i], db_i);
        }
    }
}

void PIRServer::SetupDB(vector<string> &keydb, vector<string> &elems)
{
    this->pir_db.resize(0);
    populate_db(keydb);
    for (int i = 0; i < pir_num_obj; i++)
    {
        vector<uint64_t> v;
        for (int j = 0; j < (pir_obj_size / 2); j++)
        { // 2 bytes each plaintxt slot
            uint64_t tem = 0;
            if (i < elems.size() && 2 * j < elems[i].size())
            {
                tem = static_cast<int>(elems[i][2 * j]);
                if ((2 * j + 1) < elems[i].size())
                {
                    tem = 256 * tem + static_cast<int>(elems[i][2 * j + 1]);
                }
            }
            v.push_back(tem);
        }
        pir_db.push_back(v);
    }

    set_pir_db(pir_db);
    // cout << "DB population complete!" << endl;
}

void PIRServer::QueryExpand(std::stringstream &qss)
{
    pthread_t query_expansion_thread[NUM_COL];
    int expansion_thread_id[NUM_COL];
    for (int i = 0; i < NUM_COL; i++)
    {
        expansion_thread_id[i] = i;
    }

    this->expanded_query.resize(NUM_COL);

    for (int i = 0; i < NUM_COL; i++)
    {
        vector<uint64_t> mat(N, 0ULL);
        Plaintext pt;
        for (int j = i * (N / (2 * NUM_COL)); j < (i + 1) * (N / (2 * NUM_COL)); j++)
        {
            mat[j] = mat[j + (N / 2)] = 1;
        }
        batch_encoder->encode(mat, pt);
        evaluator->transform_to_ntt_inplace(pt, context->first_parms_id());
        masks.push_back(pt);
    }

    server_query_ct.load(*context, qss); // load query ciphertext

    my_transform_to_ntt_inplace(*context, server_query_ct, TOTAL_MACHINE_THREAD);
    PIRServer::ExpandQueryStructure *expand_query_structure_ptr[NUM_COL];
    for (int i = 0; i < NUM_COL; i++)
    {
        expand_query_structure_ptr[i] = new PIRServer::ExpandQueryStructure(expansion_thread_id[i], this);
        if (pthread_create(&(query_expansion_thread[i]), NULL, expand_query, static_cast<void *>(expand_query_structure_ptr[i])))
        {
            printf("Error creating expansion thread");
        }
    }
    for (int i = 0; i < NUM_COL; i++)
    {
        pthread_join(query_expansion_thread[i], NULL);
        delete expand_query_structure_ptr[i];
    }
}

void PIRServer::Process1()
{
    this->multimap_row_result.resize(num_multimap);
    for (vector<Ciphertext> &e : this->multimap_row_result)
    {
        e.resize(NUM_ROW);
    }
    for (size_t db_i = 0; db_i < this->num_multimap; db_i++)
    {
        pthread_t row_process_thread[NUM_ROW_THREAD];
        int row_thread_id[NUM_ROW_THREAD];
        for (int i = 0; i < NUM_ROW_THREAD; i++)
        {
            row_thread_id[i] = i;
        }

        PIRServer::ProcessRowStructure *process_row_structure_ptr[NUM_ROW_THREAD];
        if (NUM_ROW_THREAD == 1)
        {
            process_row_structure_ptr[0] = new PIRServer::ProcessRowStructure(row_thread_id[0], db_i, this);
            process_rows(static_cast<void *>(process_row_structure_ptr[0]));
            delete process_row_structure_ptr[0];
        }
        else
        {
            for (int i = 0; i < NUM_ROW_THREAD; i++)
            {
                process_row_structure_ptr[i] = new PIRServer::ProcessRowStructure(row_thread_id[i], db_i, this);
                if (pthread_create(&(row_process_thread[i]), NULL, process_rows, static_cast<void *>(process_row_structure_ptr[i])))
                {
                    printf("Error creating processing thread");
                }
            }

            for (int i = 0; i < NUM_ROW_THREAD; i++)
            {
                pthread_join(row_process_thread[i], NULL);
                delete process_row_structure_ptr[i];
            }
        }
    }
}

void PIRServer::Process2()
{
    this->multimap_pir_results.resize(num_multimap);
    for (vector<Ciphertext> &e : this->multimap_pir_results)
    {
        e.resize(NUM_PIR_THREAD);
    }
    for (size_t db_i = 0; db_i < this->num_multimap; db_i++)
    {
        pthread_t pir_thread[NUM_PIR_THREAD];
        int pir_thread_id[NUM_PIR_THREAD];
        for (int i = 0; i < NUM_PIR_THREAD; i++)
        {
            pir_thread_id[i] = i;
        }

        PIRServer::ProcessPIRStructure *process_pir_structure_ptr[NUM_PIR_THREAD];
        for (int i = 0; i < NUM_PIR_THREAD; i++)
        {
            process_pir_structure_ptr[i] = new PIRServer::ProcessPIRStructure(pir_thread_id[i], db_i, this);
            if (pthread_create(&(pir_thread[i]), NULL, process_pir, static_cast<void *>(process_pir_structure_ptr[i])))
            {
                printf("Error creating PIR processing thread");
            }
        }

        for (int i = 0; i < NUM_PIR_THREAD; i++)
        {
            pthread_join(pir_thread[i], NULL);
            delete process_pir_structure_ptr[i];
        }
        for (int i = 1; i < NUM_PIR_THREAD; i++)
        {
            my_add_inplace(*context, multimap_pir_results[db_i][0], multimap_pir_results[db_i][i]);
        }

        // Ciphertext final_result = multimap_pir_results[db_i][0];
        // final_result.save(this->ss);
        // cout << "db_i: " << db_i << "    stream saved."
        //      << "  stream size: " << this->ss.str().size() << endl;
    }
    Ciphertext final_result = multimap_pir_results[0][0];
    final_result.save(this->ss);
    for (size_t db_i = 1; db_i < this->num_multimap; db_i++)
    {
        evaluator->rotate_rows_inplace(final_result, - static_cast<int>(obj_size)/4, this->galois_keys);// right rotation
        evaluator->add_inplace(final_result, multimap_pir_results[db_i][0]);
        final_result.save(this->ss);
        // cout << "db_i: " << db_i << "    stream saved."
        //      << "  stream size: " << this->ss.str().size() << endl;
    }

}

void PIRServer::SetupDBParams(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size)
{
    this->number_of_items = number_of_items;
    this->key_size = key_size;
    this->obj_size = obj_size;
    this->NUM_COL = (int)ceil(key_size / (2.0 * PLAIN_BIT));
    this->NUM_ROW = (int)ceil(number_of_items / ((double)(N / 2)));
}

void PIRServer::SetupDBParams(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size, uint32_t num_multimap)
{
    this->number_of_items = number_of_items;
    this->key_size = key_size;
    this->obj_size = obj_size;
    this->num_multimap = num_multimap;
    this->NUM_COL = (int)ceil(key_size / (2.0 * PLAIN_BIT));
    this->NUM_ROW = (int)ceil(number_of_items / ((double)(N / 2)));
}

void PIRServer::SetupMemPool()
{
    for (int i = 0; i < NUM_COL; i++)
    {
        column_pools.emplace_back(MemoryPoolHandle::New());
    }
}

void PIRServer::SetupThreadParams()
{
    this->NUM_COL_THREAD = NUM_COL;
    this->NUM_ROW_THREAD = 1;
    int log_tmp = floor(log2(this->pir_num_columns_per_obj / 2));
    this->NUM_PIR_THREAD = (pow(2, log_tmp) < 32) ? pow(2, log_tmp) : 32;
    this->TOTAL_MACHINE_THREAD = 32;
    this->NUM_EXPANSION_THREAD = TOTAL_MACHINE_THREAD / NUM_COL_THREAD;
    this->NUM_EXPONENT_THREAD = TOTAL_MACHINE_THREAD / (NUM_COL_THREAD * NUM_ROW_THREAD);
}

void PIRServer::SetupPIRParams()
{
    this->pir_num_obj = ((N / 2) * this->NUM_ROW);
    this->pir_obj_size = this->obj_size;
    this->pir_key_size = this->key_size;
    this->pir_num_query_ciphertext = ceil(this->pir_num_obj / (double)(N / 2));
    this->pir_num_columns_per_obj = 2 * (ceil(((this->pir_obj_size / 2) * 8) / (float)(PLAIN_BIT)));
    this->pir_db_rows = ceil(this->pir_num_obj / (double)N) * this->pir_num_columns_per_obj;
}

void PIRServer::populate_db()
{
    this->db.resize(0);

    vector<vector<uint64_t>> mat_db;
    for (int i = 0; i < NUM_ROW * NUM_COL; i++)
    {
        vector<uint64_t> v(N, 0ULL);
        mat_db.push_back(v);
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];

    for (uint32_t row = 0; row < NUM_ROW * (N / 2); row++)
    {
        uint32_t row_in_vector = row % (N / 2);
        uint32_t val = row + 1;
        const char str[] = {val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF, 0};
        sha256(str, 4, hash);
        for (int col = 0; col < NUM_COL; col++)
        {
            int vector_idx = (row / (N / 2)) * NUM_COL + col;
            mat_db[vector_idx][row_in_vector] = (uint64_t(hash[4 * col]) << 8) + hash[4 * col + 1];
            mat_db[vector_idx][row_in_vector + (N / 2)] = (uint64_t(hash[4 * col + 2]) << 8) + hash[4 * col + 3];
        }
    }

    for (int i = 0; i < NUM_ROW; i++)
    {
        vector<Plaintext> row_partition;
        for (int j = 0; j < NUM_COL; j++)
        {
            Plaintext pt;
            batch_encoder->encode(mat_db[i * NUM_COL + j], pt);
            row_partition.push_back(pt);
        }
        db.push_back(row_partition);
    }
    return;
}

void PIRServer::populate_multimap_db()
{
    this->multimap_db.resize(this->num_multimap);
    for (vector<vector<Plaintext>> &e : this->multimap_db)
    {
        e.resize(0);
    }

    for (size_t db_i = 0; db_i < this->num_multimap; db_i++)
    {
        vector<vector<uint64_t>> mat_db;
        for (int i = 0; i < NUM_ROW * NUM_COL; i++)
        {
            vector<uint64_t> v(N, 0ULL);
            mat_db.push_back(v);
        }
        unsigned char hash[SHA256_DIGEST_LENGTH];

        for (uint32_t row = 0; row < NUM_ROW * (N / 2); row++)
        {
            uint32_t row_in_vector = row % (N / 2);
            uint32_t val = row + 1;
            const char str[] = {val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF, 0};
            sha256(str, 4, hash);
            for (int col = 0; col < NUM_COL; col++)
            {
                int vector_idx = (row / (N / 2)) * NUM_COL + col;
                mat_db[vector_idx][row_in_vector] = (uint64_t(hash[4 * col]) << 8) + hash[4 * col + 1];
                mat_db[vector_idx][row_in_vector + (N / 2)] = (uint64_t(hash[4 * col + 2]) << 8) + hash[4 * col + 3];
            }
        }

        for (int i = 0; i < NUM_ROW; i++)
        {
            vector<Plaintext> row_partition;
            for (int j = 0; j < NUM_COL; j++)
            {
                Plaintext pt;
                batch_encoder->encode(mat_db[i * NUM_COL + j], pt);
                row_partition.push_back(pt);
            }
            multimap_db[db_i].push_back(row_partition);
        }
    }
    return;
}

void PIRServer::pareto_multimap_db()
{
    assert(this->keyword_freq_ptr != nullptr);

    vector<uint64_t> *key_ptr = this->keyword_freq_ptr.get(); // sort key

    this->multikey_db.resize(this->num_multimap, vector<uint32_t>(0)); // build key sub dbs
    uint32_t index = 0, populate_key = 1;                              // INVALID_KEY = 0

    for (uint32_t i = 0; i < (*key_ptr).size(); i++)
    {
        for (uint32_t j = 0; j < (*key_ptr)[i]; j++)
        {
            multikey_db[index % this->num_multimap].push_back(populate_key);
            index++;
        }
        populate_key++;
    }
    while (index != this->number_of_items * this->num_multimap)
    { // pad INVALID_KEY = 0
        multikey_db[index % this->num_multimap].push_back(PIRServer::INVALID_KEY);
        index++;
    }

    // ofstream logfile("/home/yuance/Work/Encryption/PIR/code/PIR/Pantheon/http/SingleServer/bin/log.csv");
    // if (logfile.is_open())
    // {
    //     for (const auto sub : multikey_db)
    //     {
    //         for (const uint64_t e : sub)
    //         {
    //             logfile << e << ",";
    //         }
    //         logfile << endl;
    //     }
    //     logfile.close();
    // }

    this->multimap_db.resize(this->num_multimap);
    for (vector<vector<Plaintext>> &e : this->multimap_db)
    {
        e.resize(0);
    }

    for (size_t db_i = 0; db_i < this->num_multimap; db_i++)
    {
        vector<vector<uint64_t>> mat_db;
        for (int i = 0; i < NUM_ROW * NUM_COL; i++)
        {
            vector<uint64_t> v(N, 0ULL);
            mat_db.push_back(v);
        }
        unsigned char hash[SHA256_DIGEST_LENGTH];

        for (uint32_t row = 0; row < NUM_ROW * (N / 2); row++)
        {
            uint32_t key;
            if (row < multikey_db[db_i].size())
                key = multikey_db[db_i][row];
            else
                key = PIRServer::INVALID_KEY;
            uint32_t val = key;
            uint32_t row_in_vector = row % (N / 2);
            const char str[] = {val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF, 0};
            sha256(str, 4, hash);
            for (int col = 0; col < NUM_COL; col++)
            { // key bitsize
                int vector_idx = (row / (N / 2)) * NUM_COL + col;
                mat_db[vector_idx][row_in_vector] = (uint64_t(hash[4 * col]) << 8) + hash[4 * col + 1];
                mat_db[vector_idx][row_in_vector + (N / 2)] = (uint64_t(hash[4 * col + 2]) << 8) + hash[4 * col + 3];
            }
        }

        for (int i = 0; i < NUM_ROW; i++)
        {
            vector<Plaintext> row_partition;
            for (int j = 0; j < NUM_COL; j++)
            {
                Plaintext pt;
                batch_encoder->encode(mat_db[i * NUM_COL + j], pt);
                row_partition.push_back(pt);
            }
            multimap_db[db_i].push_back(row_partition);
        }
    }
    return;
}

void PIRServer::populate_db(vector<string> &keydb)
{
    vector<vector<uint64_t>> mat_db;
    for (int i = 0; i < NUM_ROW * NUM_COL; i++)

    {
        vector<uint64_t> v(N, 0ULL);
        mat_db.push_back(v);
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    for (uint32_t row = 0; row < NUM_ROW * (N / 2); row++)
    {
        uint32_t row_in_vector = row % (N / 2);
        int j = 0;
        string key;
        char str[NUM_COL * 4];
        if (row < keydb.size())
        {
            key = keydb[row];
            for (j; j < key.size(); j++)
            {
                str[j] = key[j];
            }
        }
        for (j; j < 4 * NUM_COL; j++)
        {
            str[j] = 0;
        }
        sha256(str, 4 * NUM_COL, hash);
        for (int col = 0; col < NUM_COL; col++)
        {
            int vector_idx = (row / (N / 2)) * NUM_COL + col;
            mat_db[vector_idx][row_in_vector] = (uint64_t(hash[4 * col]) << 8) + hash[4 * col + 1];
            mat_db[vector_idx][row_in_vector + (N / 2)] = (uint64_t(hash[4 * col + 2]) << 8) + hash[4 * col + 3];
        }
    }
    for (int i = 0; i < NUM_ROW; i++)
    {
        vector<Plaintext> row_partition;
        for (int j = 0; j < NUM_COL; j++)
        {
            Plaintext pt;
            batch_encoder->encode(mat_db[i * NUM_COL + j], pt);
            row_partition.push_back(pt);
        }
        db.push_back(row_partition);
    }
    return;
}

std::pair<unique_ptr<vector<uint64_t>>, uint64_t> PIRServer::generateDiscretePareto(double alpha, uint64_t maxVal, uint64_t numSamples)
{
    std::mt19937 rng(std::random_device{}());
    std::uniform_real_distribution<double> uniformDist(0.0, 1.0);
    std::unique_ptr<std::vector<uint64_t>> _data = std::make_unique<std::vector<uint64_t>>();
    uint64_t counter = 0, total_item = 0, x = 0, num_keys = 0;
    while (total_item < numSamples)
    {

        double u = uniformDist(rng);
        x = static_cast<uint64_t>(std::pow(u, -1.0 / alpha));
        if (x > maxVal)
        {
            x = maxVal;
        }
        _data->push_back(x);
        total_item += x;
        counter++;
    }
    std::cout << "[1. sampling] Total items generated: " << total_item << std::endl;
    return {std::move(_data), total_item};
}

void PIRServer::sha256(const char *str, int len, unsigned char *dest)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, len);
    SHA256_Final(dest, &sha256);
}

void PIRServer::set_pir_db(std::vector<std::vector<uint64_t>> db)
{
    assert(db.size() == pir_num_obj);
    std::vector<std::vector<uint64_t>> extended_db(pir_db_rows);
    for (int i = 0; i < pir_db_rows; i++)
    {
        extended_db[i] = std::vector<uint64_t>(N, 1ULL);
    }
    int row_size = N / 2;

    for (int i = 0; i < pir_num_obj; i++)
    {
        std::vector<uint64_t> temp = db[i];

        int row = (i / row_size);
        int col = (i % row_size);
        for (int j = 0; j < pir_num_columns_per_obj / 2; j++)
        {
            extended_db[row][col] = temp[j];
            extended_db[row][col + row_size] = temp[j + (pir_num_columns_per_obj / 2)];
            row += pir_num_query_ciphertext;
        }
    }
    pir_encode_db(extended_db);
    return;
}

void PIRServer::pir_encode_db(std::vector<std::vector<uint64_t>> db)
{
    pir_encoded_db = std::vector<seal::Plaintext>(db.size());
    for (int i = 0; i < db.size(); i++)
    {
        batch_encoder->encode(db[i], pir_encoded_db[i]);
        evaluator->transform_to_ntt_inplace(pir_encoded_db[i], compact_pid);
    }
}

void PIRServer::set_pir_multimap_db(std::vector<std::vector<uint64_t>> db, size_t db_i)
{
    assert(db.size() == pir_num_obj);
    std::vector<std::vector<uint64_t>> extended_db(pir_db_rows);
    for (int i = 0; i < pir_db_rows; i++)
    {
        extended_db[i] = std::vector<uint64_t>(N, 1ULL);
    }
    int row_size = N / 2;

    for (int i = 0; i < pir_num_obj; i++)
    {
        std::vector<uint64_t> temp = db[i];

        int row = (i / row_size);
        int col = (i % row_size);
        for (int j = 0; j < pir_num_columns_per_obj / 2; j++)
        {
            extended_db[row][col] = temp[j];
            extended_db[row][col + row_size] = temp[j + (pir_num_columns_per_obj / 2)];
            row += pir_num_query_ciphertext;
        }
    }
    pir_encode_multimap_db(extended_db, db_i);
    return;
}

void PIRServer::pir_encode_multimap_db(std::vector<std::vector<uint64_t>> db, size_t db_i)
{
    multimap_pir_encoded_db[db_i] = std::vector<seal::Plaintext>(db.size());
    for (int i = 0; i < db.size(); i++)
    {
        batch_encoder->encode(db[i], multimap_pir_encoded_db[db_i][i]);
        evaluator->transform_to_ntt_inplace(multimap_pir_encoded_db[db_i][i], compact_pid);
    }
}

void *PIRServer::expand_query(void *arg)
{
    PIRServer::ExpandQueryStructure *args_ptr = static_cast<PIRServer::ExpandQueryStructure *>(arg);
    int id = args_ptr->id;
    size_t db_i = args_ptr->db_i;
    PIRServer *server = args_ptr->server;

    server->expanded_query[id] = server->server_query_ct;
    my_multiply_plain_ntt(*(server->context), server->expanded_query[id], server->masks[id], server->NUM_EXPANSION_THREAD);
    my_transform_from_ntt_inplace(*(server->context), server->expanded_query[id], server->NUM_EXPANSION_THREAD);
    Ciphertext temp_ct;

    for (int i = N / (2 * server->NUM_COL); i < N / 2; i *= 2)
    {
        temp_ct = server->expanded_query[id];
        my_rotate_internal(*(server->context), temp_ct, i, server->galois_keys, server->column_pools[id], server->NUM_EXPANSION_THREAD);
        my_add_inplace(*(server->context), server->expanded_query[id], temp_ct);
    }
    return nullptr;
}

void *PIRServer::process_rows(void *arg)
{
    PIRServer::ProcessRowStructure *args_ptr = static_cast<PIRServer::ProcessRowStructure *>(arg);
    int id = args_ptr->id; // row thread ID
    size_t db_i = args_ptr->db_i;
    PIRServer *server = args_ptr->server;

    Ciphertext column_results[server->NUM_COL];
    vector<column_thread_arg> column_args;
    vector<mult_thread_arg> mult_args;

    for (int i = 0; i < server->NUM_COL_THREAD; i++)
    {
        column_args.push_back(column_thread_arg(i, id, column_results));
    }
    for (int i = 0; i < server->NUM_COL_THREAD; i++)
    {
        mult_args.push_back(mult_thread_arg(i, 1, column_results)); // ??????
    }
    int num_row_per_thread = server->NUM_ROW / server->NUM_ROW_THREAD;
    int start_idx = num_row_per_thread * id;
    int end_idx = start_idx + num_row_per_thread;

    pthread_t col_process_thread[server->NUM_COL_THREAD];
    pthread_t col_mult_thread[server->NUM_COL_THREAD];

    for (int row_idx = start_idx; row_idx < end_idx; row_idx++)
    {
        // time_start = chrono::high_resolution_clock::now();

        PIRServer::ProcessColStructure *process_col_structure_ptr[server->NUM_COL_THREAD];
        for (int i = 0; i < server->NUM_COL_THREAD; i++)
        {
            column_args[i].row_idx = row_idx;
            process_col_structure_ptr[i] = new PIRServer::ProcessColStructure(column_args[i], db_i, server);
            if (pthread_create(&(col_process_thread[i]), NULL, process_columns, static_cast<void *>(process_col_structure_ptr[i])))
            {
                printf("Error creating column processing thread");
            }
        }

        for (int i = 0; i < server->NUM_COL_THREAD; i++)
        {
            pthread_join(col_process_thread[i], NULL);
            delete process_col_structure_ptr[i];
        }

        PIRServer::MultiplyColStructure *mul_col_structure_ptr[server->NUM_COL_THREAD];
        for (int diff = 2; diff <= server->NUM_COL_THREAD; diff *= 2)
        {

            for (int i = 0; i < mult_args.size(); i++)
            {
                mult_args[i].diff = diff;
            }
            for (int i = 0; i < server->NUM_COL_THREAD; i += diff)
            {
                mul_col_structure_ptr[i] = new PIRServer::MultiplyColStructure(mult_args[i], db_i, server);
                if (pthread_create(&(col_mult_thread[i]), NULL, multiply_columns, static_cast<void *>(mul_col_structure_ptr[i])))
                {
                    printf("Error creating column processing thread");
                }
            }

            for (int i = 0; i < server->NUM_COL_THREAD; i += diff)
            {
                pthread_join(col_mult_thread[i], NULL);
                delete mul_col_structure_ptr[i];
            }
        }

        Ciphertext temp_ct = column_results[0];
        my_conjugate_internal(*(server->context), temp_ct, server->galois_keys, server->column_pools[0], server->TOTAL_MACHINE_THREAD / server->NUM_ROW_THREAD);

        my_bfv_multiply(*(server->context), column_results[0], temp_ct, server->column_pools[0], server->TOTAL_MACHINE_THREAD / server->NUM_ROW_THREAD);
        my_relinearize_internal(*(server->context), column_results[0], server->relin_keys, 2, MemoryManager::GetPool(), server->TOTAL_MACHINE_THREAD / server->NUM_ROW_THREAD);
        my_transform_to_ntt_inplace(*(server->context), column_results[0], server->TOTAL_MACHINE_THREAD / server->NUM_ROW_THREAD);
        server->multimap_row_result[db_i][row_idx] = column_results[0];
    }
    return nullptr;
}

void *PIRServer::process_columns(void *arg)
{
    PIRServer::ProcessColStructure *args_ptr = static_cast<PIRServer::ProcessColStructure *>(arg);
    column_thread_arg col_arg = args_ptr->col_arg;
    size_t db_i = args_ptr->db_i;
    PIRServer *server = args_ptr->server;

    vector<unsigned long> exp_time;
    unsigned long exponent_time = 0;
    int num_col_per_thread = server->NUM_COL / server->NUM_COL_THREAD;
    int start_idx = num_col_per_thread * col_arg.col_id;
    int end_idx = start_idx + num_col_per_thread;
    for (int i = start_idx; i < end_idx; i++)
    {
        Ciphertext sub;
        server->evaluator->sub_plain(server->expanded_query[i], server->multimap_db[db_i][col_arg.row_idx][i], sub);

        for (int k = 0; k < 16; k++)
        {
            my_bfv_square(*(server->context), sub, server->column_pools[i], server->NUM_EXPONENT_THREAD);
            my_relinearize_internal(*(server->context), sub, server->relin_keys, 2, server->column_pools[i], server->NUM_EXPONENT_THREAD);
        }
        for (int k = 0; k < MOD_SWITCH_COUNT; k++)
        {
            my_mod_switch_scale_to_next(*(server->context), sub, sub, server->column_pools[i], server->NUM_EXPONENT_THREAD);
        }
        server->evaluator->sub(server->one_ct, sub, (col_arg.column_result)[i]);
    }
    return nullptr;
}

void *PIRServer::multiply_columns(void *arg)
{
    PIRServer::MultiplyColStructure *args_ptr = static_cast<PIRServer::MultiplyColStructure *>(arg);
    mult_thread_arg mult_arg = args_ptr->mult_arg;
    size_t db_i = args_ptr->db_i;
    PIRServer *server = args_ptr->server;

    Ciphertext *column_results = mult_arg.column_result;
    int id = mult_arg.id;
    int diff = mult_arg.diff;
    int num_threads = server->TOTAL_MACHINE_THREAD / (server->NUM_COL / diff);

    my_bfv_multiply(*(server->context), column_results[id], column_results[id + (diff / 2)], server->column_pools[id], num_threads);
    my_relinearize_internal(*(server->context), column_results[id], server->relin_keys, 2, server->column_pools[id], num_threads);
    return nullptr;
}

void *PIRServer::process_pir(void *arg)
{
    PIRServer::ProcessPIRStructure *args_ptr = static_cast<PIRServer::ProcessPIRStructure *>(arg);
    int my_id = args_ptr->my_id;
    size_t db_i = args_ptr->db_i;
    PIRServer *server = args_ptr->server;

    int column_per_thread = (server->pir_num_columns_per_obj / 2) / server->NUM_PIR_THREAD;
    int start_idx = my_id * column_per_thread;
    int end_idx = start_idx + column_per_thread - 1;

    server->multimap_pir_results[db_i][my_id] = get_sum(server->multimap_row_result[db_i], start_idx, end_idx, server, db_i);

    int mask = 1;
    while (mask <= start_idx)
    {
        if (start_idx & mask)
        {
            my_rotate_internal(*(server->context), server->multimap_pir_results[db_i][my_id], -mask, server->galois_keys, MemoryManager::GetPool(), server->TOTAL_MACHINE_THREAD / server->NUM_PIR_THREAD);
        }
        mask <<= 1;
    }
    return nullptr;
}

Ciphertext PIRServer::get_sum(vector<Ciphertext> &query, uint32_t start, uint32_t end, PIRServer *server)
{
    if (start != end)
    {
        int count = (end - start) + 1;
        int next_power_of_two = get_next_power_of_two(count);
        int mid = next_power_of_two / 2;

        seal::Ciphertext left_sum = get_sum(query, start, start + mid - 1, server);
        seal::Ciphertext right_sum = get_sum(query, start + mid, end, server);
        my_rotate_internal(*server->context, right_sum, -mid, server->galois_keys, server->column_pools[0], server->TOTAL_MACHINE_THREAD / server->NUM_PIR_THREAD);
        my_add_inplace(*server->context, left_sum, right_sum);
        return left_sum;
    }
    else
    {

        seal::Ciphertext column_sum = query[0];
        seal::Ciphertext temp_ct;
        my_multiply_plain_ntt(*server->context, column_sum, server->pir_encoded_db[server->pir_num_query_ciphertext * start], server->TOTAL_MACHINE_THREAD / server->NUM_PIR_THREAD);

        for (int j = 1; j < server->pir_num_query_ciphertext; j++)
        {
            temp_ct = query[j];
            my_multiply_plain_ntt(*server->context, temp_ct, server->pir_encoded_db[server->pir_num_query_ciphertext * start + j], server->TOTAL_MACHINE_THREAD / server->NUM_PIR_THREAD);
            my_add_inplace(*server->context, column_sum, temp_ct);
        }
        my_transform_from_ntt_inplace(*server->context, column_sum, server->TOTAL_MACHINE_THREAD / server->NUM_PIR_THREAD);
        return column_sum;
    }
}

Ciphertext PIRServer::get_sum(vector<Ciphertext> &query, uint32_t start, uint32_t end, PIRServer *server, size_t db_i)
{
    if (start != end)
    {
        int count = (end - start) + 1;
        int next_power_of_two = get_next_power_of_two(count);
        int mid = next_power_of_two / 2;

        seal::Ciphertext left_sum = get_sum(query, start, start + mid - 1, server, db_i);
        seal::Ciphertext right_sum = get_sum(query, start + mid, end, server, db_i);
        my_rotate_internal(*server->context, right_sum, -mid, server->galois_keys, server->column_pools[0], server->TOTAL_MACHINE_THREAD / server->NUM_PIR_THREAD);
        my_add_inplace(*server->context, left_sum, right_sum);
        return left_sum;
    }
    else
    {

        seal::Ciphertext column_sum = query[0];
        seal::Ciphertext temp_ct;
        my_multiply_plain_ntt(*server->context, column_sum, server->multimap_pir_encoded_db[db_i][server->pir_num_query_ciphertext * start], server->TOTAL_MACHINE_THREAD / server->NUM_PIR_THREAD);

        for (int j = 1; j < server->pir_num_query_ciphertext; j++)
        {
            temp_ct = query[j];
            my_multiply_plain_ntt(*server->context, temp_ct, server->multimap_pir_encoded_db[db_i][server->pir_num_query_ciphertext * start + j], server->TOTAL_MACHINE_THREAD / server->NUM_PIR_THREAD);
            my_add_inplace(*server->context, column_sum, temp_ct);
        }
        my_transform_from_ntt_inplace(*server->context, column_sum, server->TOTAL_MACHINE_THREAD / server->NUM_PIR_THREAD);
        return column_sum;
    }
}

uint32_t PIRServer::get_next_power_of_two(uint32_t number)
{
    if (!(number & (number - 1)))
    {
        return number;
    }

    uint32_t number_of_bits = get_number_of_bits(number);
    return (1 << number_of_bits);
}

uint32_t PIRServer::get_number_of_bits(uint64_t number)
{
    uint32_t count = 0;
    while (number)
    {
        count++;
        number /= 2;
    }
    return count;
}

void PIRServer::DBIndexSearch(uint32_t desired_index, vector<uint32_t> &db_index)
{
    for (uint32_t db_i = 0; db_i < this->num_multimap; db_i++)
    {
        for (uint32_t row_index = 0; row_index < this->multikey_db[db_i].size(); row_index++)
        {
            if (this->multikey_db[db_i][row_index] == desired_index)
            {
                db_index.push_back(row_index);
                break;
            }
             db_index.push_back(PIRServer::INVALID_INDEX);
        }
    }
}
