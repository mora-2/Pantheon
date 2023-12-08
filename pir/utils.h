#pragma once

#include <vector>
#include <memory>
#include <map>
#include "seal/context.h"
#include "seal/relinkeys.h"
#include "seal/memorymanager.h"
#include "seal/ciphertext.h"
#include "seal/plaintext.h"
#include "seal/galoiskeys.h"
#include "seal/util/pointer.h"
#include "seal/secretkey.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/common.h"
#include "seal/evaluator.h"
#include "seal/util/common.h"
#include "seal/util/galois.h"
#include "seal/util/numth.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include "seal/util/defines.h"
#include "seal/util/uintarith.h"
#include <algorithm>
#include "seal/util/scalingvariant.h"
#include <cmath>
#include <functional>
#include <iostream>
#include <chrono>

#include "omp.h"

using namespace seal;
using namespace seal::util;

using namespace std;

// int NUM_OMP_THREAD = 4;
void my_add_inplace(SEALContext &context_, Ciphertext &encrypted1, Ciphertext &encrypted2);
void my_bfv_square(SEALContext &context_, Ciphertext &encrypted, MemoryPoolHandle pool, int num_threads);
void my_fastbconv_m_tilde(const RNSTool *rns_tool, ConstRNSIter input, RNSIter destination, MemoryPoolHandle pool, int num_threads);
void my_fast_convert_array(const Pointer<BaseConverter> &conv, ConstRNSIter in, RNSIter out, MemoryPoolHandle pool, int num_threads);
void my_sm_mrq(const RNSTool *rns_tool, ConstRNSIter input, RNSIter destination, MemoryPoolHandle pool, int num_threads);
void my_fast_floor(const RNSTool *rns_tool, ConstRNSIter input, RNSIter destination, MemoryPoolHandle pool, int num_threads);
void my_fastbconv_sk(const RNSTool *rns_tool, ConstRNSIter input, RNSIter destination, MemoryPoolHandle pool, int num_threads);

void my_relinearize_internal(SEALContext &context_, Ciphertext &encrypted, const RelinKeys &relin_keys, size_t destination_size, MemoryPoolHandle pool, int num_threads);
// void my_switch_key_inplace( SEALContext &context_,
//         Ciphertext &encrypted, ConstRNSIter target_iter, const KSwitchKeys &kswitch_keys, size_t kswitch_keys_index,
//         MemoryPoolHandle pool);
void my_bfv_multiply(SEALContext &context_, Ciphertext &encrypted1, Ciphertext &encrypted2, MemoryPoolHandle pool, int num_threads);
void my_mod_switch_scale_to_next(SEALContext &context_, Ciphertext &encrypted, Ciphertext &destination, MemoryPoolHandle pool, int num_threads);
void my_transform_to_ntt_inplace(SEALContext &context_, Ciphertext &encrypted, int num_threads);
void my_transform_from_ntt_inplace(SEALContext &context_, Ciphertext &encrypted_ntt, int num_threads);
void my_multiply_plain_ntt(SEALContext &context_, Ciphertext &encrypted_ntt, const Plaintext &plain_ntt, int num_threads);
void my_rotate_internal(SEALContext context_, Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys, MemoryPoolHandle pool, int num_threads);
void my_conjugate_internal(SEALContext context_, Ciphertext &encrypted, const GaloisKeys &galois_keys, MemoryPoolHandle pool, int num_threads);
void my_apply_galois_inplace(SEALContext context_, Ciphertext &encrypted, uint32_t galois_elt, const GaloisKeys &galois_keys, MemoryPoolHandle pool, int num_threads);
void my_switch_key_inplace(
    SEALContext &context_, Ciphertext &encrypted, ConstRNSIter target_iter, const KSwitchKeys &kswitch_keys, size_t kswitch_keys_index,
    MemoryPoolHandle pool, int num_threads);

inline void my_inverse_ntt_negacyclic_harvey(PolyIter operand, std::size_t size, ConstNTTTablesIter tables)
{
    // SEAL_ITERATE(operand, size, [&](auto I) { inverse_ntt_negacyclic_harvey(I, operand.coeff_modulus_size(), tables);});
    for (int i = 0; i < size; i++)
    {
        for (int j = 0; j < operand.coeff_modulus_size(); j++)
        {
            inverse_ntt_negacyclic_harvey_lazy(operand[i][j], tables[j]);
        }
    }
}

inline void my_add_poly_coeffmod(
    ConstRNSIter operand1, ConstRNSIter operand2, std::size_t coeff_modulus_size, ConstModulusIter modulus,
    RNSIter result, int num_threads)
{
    auto poly_modulus_degree = result.poly_modulus_degree();

#pragma omp parallel for num_threads(num_threads)
    for (int i = 0; i < coeff_modulus_size; i++)
    {
        add_poly_coeffmod(operand1[i], operand2[i], poly_modulus_degree, modulus[i], result[i]);
    }
}

inline void my_dyadic_product_coeffmod(
    ConstRNSIter operand1, ConstRNSIter operand2, std::size_t coeff_modulus_size, ConstModulusIter modulus,
    RNSIter result, int num_threads)
{
    auto poly_modulus_degree = result.poly_modulus_degree();
#pragma omp parallel for num_threads(num_threads)
    for (int i = 0; i < coeff_modulus_size; i++)
    {
        dyadic_product_coeffmod(operand1[i], operand2[i], poly_modulus_degree, modulus[i], result[i]);
    }
}

inline void my_ntt_negacyclic_harvey_lazy(
    RNSIter operand, std::size_t coeff_modulus_size, ConstNTTTablesIter tables, int num_threads)
{
#pragma omp paralle for num_threads(num_threads)
    for (int i = 0; i < coeff_modulus_size; i++)
    {
        ntt_negacyclic_harvey_lazy(operand[i], tables[i]);
    }
}

inline void my_multiply_poly_scalar_coeffmod(ConstRNSIter poly, std::size_t coeff_modulus_size, std::uint64_t scalar, ConstModulusIter modulus,
                                             RNSIter result, int num_threads)
{
    auto poly_modulus_degree = result.poly_modulus_degree();

#pragma omp parallel for num_threads(num_threads)
    for (int i = 0; i < coeff_modulus_size; i++)
    {
        multiply_poly_scalar_coeffmod(poly[i], poly_modulus_degree, scalar, modulus[i], result[i]);
    }
}
