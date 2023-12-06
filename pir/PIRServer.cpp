#include "PIRServer.h"
#include "globals.h"
#include <cmath>
#include <set>

PIRServer::PIRServer(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size)
{
    this->SetupDBParams(number_of_items, key_size, obj_size);
    this->SetupThreadParams();
    this->SetupPIRParams();
}

void PIRServer::SetupDBParams(uint64_t number_of_items, uint32_t key_size, uint32_t obj_size)
{
    this->number_of_items = number_of_items;
    this->key_size = key_size;
    this->obj_size = obj_size;
    this->NUM_COL = (int)ceil(key_size / (2.0 * PLAIN_BIT));
    this->NUM_ROW = (int)ceil(number_of_items / ((double)(N / 2)));
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

void PIRServer::SetupCryptoParams()
{
    this->parms = std::make_unique<EncryptionParameters>(scheme_type::bfv);
    parms->set_poly_modulus_degree(N);
    parms->set_coeff_modulus(CoeffModulus::Create(N, CT_PRIMES));
    parms->set_plain_modulus(PLAIN_MODULUS);

    this->context = std::make_unique<SEALContext>(parms);
    this->keygen = std::make_unique<KeyGenerator>(*context);
    this->secret_key = this->keygen->secret_key();
    this->keygen->create_relin_keys(this->relin_keys);

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
    this->keygen->create_galois_keys(vector<int>(rotation_steps.begin(), rotation_steps.end()), this->galois_keys);


    
}
