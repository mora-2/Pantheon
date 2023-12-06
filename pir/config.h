#pragma once 

#include "seal/seal.h"

using namespace seal;

struct column_thread_arg
{

    int col_id;
    int row_idx;
    Ciphertext *column_result;
    column_thread_arg(int c_id, int r_idx, Ciphertext *res)
    {
        col_id = c_id;
        row_idx = r_idx;
        column_result = res;
    }
};

struct mult_thread_arg
{
    int id;
    int diff;
    Ciphertext *column_result;
    mult_thread_arg(int _id, int _diff, Ciphertext *_column_result)
    {
        id = _id;
        diff = _diff;
        column_result = _column_result;
    }
};
