#include "PIRServer.h"
#include "globals.h"
#include <cmath>
#include <set>
#include <openssl/sha.h>
#include "config.h"
#include "utils.hpp"
#include <cassert>

PIRServer::PIRServer(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size)
{
    this->SetupDBParams(number_of_items, key_size, obj_size);
    this->SetupMemPool();
    this->SetupThreadParams();
    this->SetupPIRParams();
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
    this->one_ct->load(*context, one_ct_ss);
}

void PIRServer::SetupDB()
{
    populate_db();
    vector<vector<uint64_t>> pir_db; // 64 bit placeholder for 16 bit plaintext coefficients

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
    for (int i = 0; i < NUM_COL; i++)
    {
        if (pthread_create(&(query_expansion_thread[i]), NULL, expand_query, (void *)&(expansion_thread_id[i])))
        {
            printf("Error creating expansion thread");
        }
    }
    for (int i = 0; i < NUM_COL; i++)
    {
        pthread_join(query_expansion_thread[i], NULL);
    }
}

void PIRServer::Process1()
{
    this->row_result.resize(NUM_ROW);
    pthread_t row_process_thread[NUM_ROW_THREAD];
    int row_thread_id[NUM_ROW_THREAD];
    for (int i = 0; i < NUM_ROW_THREAD; i++)
    {
        row_thread_id[i] = i;
    }

    if (NUM_ROW_THREAD == 1)
    {
        process_rows((void *)&(row_thread_id[0]));
    }
    else
    {
        for (int i = 0; i < NUM_ROW_THREAD; i++)
        {
            if (pthread_create(&(row_process_thread[i]), NULL, process_rows, (void *)&(row_thread_id[i])))
            {
                printf("Error creating processing thread");
            }
        }

        for (int i = 0; i < NUM_ROW_THREAD; i++)
        {
            pthread_join(row_process_thread[i], NULL);
        }
    }
}

void PIRServer::Process2()
{
    this->pir_results.resize(NUM_PIR_THREAD);

    pthread_t pir_thread[NUM_PIR_THREAD];
    int pir_thread_id[NUM_PIR_THREAD];
    for (int i = 0; i < NUM_PIR_THREAD; i++)
    {
        pir_thread_id[i] = i;
    }

    for (int i = 0; i < NUM_PIR_THREAD; i++)
    {
        if (pthread_create(&(pir_thread[i]), NULL, process_pir, (void *)&(pir_thread_id[i])))
        {
            printf("Error creating PIR processing thread");
        }
    }

    for (int i = 0; i < NUM_PIR_THREAD; i++)
    {
        pthread_join(pir_thread[i], NULL);
    }
    for (int i = 1; i < NUM_PIR_THREAD; i++)
    {
        my_add_inplace(*context, pir_results[0], pir_results[i]);
    }

    Ciphertext final_result = pir_results[0];
    final_result.save(ss);
}

void PIRServer::SetupDBParams(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size)
{
    this->number_of_items = number_of_items;
    this->key_size = key_size;
    this->obj_size = obj_size;
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
    this->NUM_PIR_THREAD = 32;
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

void *PIRServer::expand_query(void *arg)
{
    int id = *((int *)arg);

    expanded_query[id] = server_query_ct;
    my_multiply_plain_ntt(*context, expanded_query[id], masks[id], NUM_EXPANSION_THREAD);
    my_transform_from_ntt_inplace(*context, expanded_query[id], NUM_EXPANSION_THREAD);
    Ciphertext temp_ct;

    for (int i = N / (2 * NUM_COL); i < N / 2; i *= 2)
    {
        temp_ct = expanded_query[id];
        my_rotate_internal(*context, temp_ct, i, galois_keys, column_pools[id], NUM_EXPANSION_THREAD);
        my_add_inplace(*context, expanded_query[id], temp_ct);
    }
    return nullptr;
}

void *PIRServer::process_rows(void *arg)
{
    int id = *((int *)arg); // row thread ID
    Ciphertext column_results[NUM_COL];
    vector<column_thread_arg> column_args;
    vector<mult_thread_arg> mult_args;

    for (int i = 0; i < NUM_COL_THREAD; i++)
    {
        column_args.push_back(column_thread_arg(i, id, column_results));
    }
    for (int i = 0; i < NUM_COL; i++)
    {
        mult_args.push_back(mult_thread_arg(i, 1, column_results));
    }
    int num_row_per_thread = NUM_ROW / NUM_ROW_THREAD;
    int start_idx = num_row_per_thread * id;
    int end_idx = start_idx + num_row_per_thread;

    pthread_t col_process_thread[NUM_COL_THREAD];
    pthread_t col_mult_thread[NUM_COL_THREAD];

    for (int row_idx = start_idx; row_idx < end_idx; row_idx++)
    {
        // time_start = chrono::high_resolution_clock::now();

        for (int i = 0; i < NUM_COL_THREAD; i++)
        {
            column_args[i].row_idx = row_idx;
            if (pthread_create(&(col_process_thread[i]), NULL, process_columns, (void *)&(column_args[i])))
            {
                printf("Error creating column processing thread");
            }
        }

        for (int i = 0; i < NUM_COL_THREAD; i++)
        {
            pthread_join(col_process_thread[i], NULL);
        }

        for (int diff = 2; diff <= NUM_COL; diff *= 2)
        {

            for (int i = 0; i < mult_args.size(); i++)
            {
                mult_args[i].diff = diff;
            }
            for (int i = 0; i < NUM_COL; i += diff)
            {
                if (pthread_create(&(col_mult_thread[i]), NULL, multiply_columns, (void *)&(mult_args[i])))
                {
                    printf("Error creating column processing thread");
                }
            }

            for (int i = 0; i < NUM_COL; i += diff)
            {
                pthread_join(col_mult_thread[i], NULL);
            }
        }

        Ciphertext temp_ct = column_results[0];
        my_conjugate_internal(*context, temp_ct, galois_keys, column_pools[0], TOTAL_MACHINE_THREAD / NUM_ROW_THREAD);

        my_bfv_multiply(*context, column_results[0], temp_ct, column_pools[0], TOTAL_MACHINE_THREAD / NUM_ROW_THREAD);
        my_relinearize_internal(*context, column_results[0], relin_keys, 2, MemoryManager::GetPool(), TOTAL_MACHINE_THREAD / NUM_ROW_THREAD);
        my_transform_to_ntt_inplace(*context, column_results[0], TOTAL_MACHINE_THREAD);
        row_result[row_idx] = column_results[0];
    }
    return nullptr;
}

void *PIRServer::process_columns(void *arg)
{
    column_thread_arg col_arg = *((column_thread_arg *)arg);
    vector<unsigned long> exp_time;
    unsigned long exponent_time = 0;
    int num_col_per_thread = NUM_COL / NUM_COL_THREAD;
    int start_idx = num_col_per_thread * col_arg.col_id;
    int end_idx = start_idx + num_col_per_thread;
    for (int i = start_idx; i < end_idx; i++)
    {
        Ciphertext sub;
        Ciphertext prod;
        evaluator->sub_plain(expanded_query[i], db[col_arg.row_idx][i], sub);

        for (int k = 0; k < 16; k++)
        {
            my_bfv_square(*context, sub, column_pools[i], NUM_EXPONENT_THREAD);
            my_relinearize_internal(*context, sub, relin_keys, 2, column_pools[i], NUM_EXPONENT_THREAD);
        }
        for (int k = 0; k < MOD_SWITCH_COUNT; k++)
        {
            my_mod_switch_scale_to_next(*context, sub, sub, column_pools[i], NUM_EXPONENT_THREAD);
        }
        evaluator->sub(*one_ct, sub, (col_arg.column_result)[i]);
    }
    return nullptr;
}

void *PIRServer::multiply_columns(void *arg)
{
    mult_thread_arg mult_arg = *((mult_thread_arg *)arg);
    Ciphertext *column_results = mult_arg.column_result;
    int id = mult_arg.id;
    int diff = mult_arg.diff;
    int num_threads = TOTAL_MACHINE_THREAD / (NUM_COL / diff);

    my_bfv_multiply(*context, column_results[id], column_results[id + (diff / 2)], column_pools[id], num_threads);
    my_relinearize_internal(*context, column_results[id], relin_keys, 2, column_pools[id], num_threads);
    return nullptr;
}

void *PIRServer::process_pir(void *arg)
{
    int my_id = *((int *)arg);
    int column_per_thread = (pir_num_columns_per_obj / 2) / NUM_PIR_THREAD;
    int start_idx = my_id * column_per_thread;
    int end_idx = start_idx + column_per_thread - 1;
    pir_results[my_id] = get_sum(row_result, start_idx, end_idx);

    int mask = 1;
    while (mask <= start_idx)
    {
        if (start_idx & mask)
        {
            my_rotate_internal(*context, pir_results[my_id], -mask, galois_keys, MemoryManager::GetPool(), TOTAL_MACHINE_THREAD / NUM_PIR_THREAD);
        }
        mask <<= 1;
    }
    return nullptr;
}

Ciphertext PIRServer::get_sum(vector<Ciphertext> &query, uint32_t start, uint32_t end)
{
    seal::Ciphertext result;

    if (start != end)
    {
        int count = (end - start) + 1;
        int next_power_of_two = get_next_power_of_two(count);
        int mid = next_power_of_two / 2;
        seal::Ciphertext left_sum = get_sum(query, start, start + mid - 1);
        seal::Ciphertext right_sum = get_sum(query, start + mid, end);
        my_rotate_internal(*context, right_sum, -mid, galois_keys, column_pools[0], TOTAL_MACHINE_THREAD / NUM_PIR_THREAD);
        my_add_inplace(*context, left_sum, right_sum);
        return left_sum;
    }
    else
    {

        seal::Ciphertext column_sum = query[0];
        seal::Ciphertext temp_ct;
        my_multiply_plain_ntt(*context, column_sum, pir_encoded_db[pir_num_query_ciphertext * start], TOTAL_MACHINE_THREAD / NUM_PIR_THREAD);

        for (int j = 1; j < pir_num_query_ciphertext; j++)
        {
            temp_ct = query[j];
            my_multiply_plain_ntt(*context, temp_ct, pir_encoded_db[pir_num_query_ciphertext * start + j], TOTAL_MACHINE_THREAD / NUM_PIR_THREAD);
            my_add_inplace(*context, column_sum, temp_ct);
        }
        my_transform_from_ntt_inplace(*context, column_sum, TOTAL_MACHINE_THREAD / NUM_PIR_THREAD);
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
