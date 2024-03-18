#include <iostream>
#include "PIRServer.h"
#include "PIRClient.h"
#include "globals.h"
#include <chrono>
using namespace std;

int main(int argc, char *argv[])
{
    map<string, uint64_t> metrics;
    uint64_t number_of_sub_items = 4'096; // 15 32'768
    uint32_t key_size = 64;
    uint32_t obj_size = 8;
    uint32_t num_multimap = 8;
    uint64_t number_of_items = number_of_sub_items * num_multimap;

    PIRServer server(number_of_sub_items, key_size, obj_size, num_multimap);
    PIRClient client(key_size, obj_size);

    /*-----------------------------------------------------------------*/
    /*                           CryptoParamSet                        */
    /*-----------------------------------------------------------------*/
    server.SetupCryptoParams();
    client.SetupCrypto(server.parms_ss);
    server.SetupKeys(client.keys_ss);

    /*-----------------------------------------------------------------*/
    /*                           OneCiphertext                         */
    /*-----------------------------------------------------------------*/
    client.SetOneCiphertext();
    server.RecOneCiphertext(client.one_ct_ss);

    /*-----------------------------------------------------------------*/
    /*                           SetupDB                               */
    /*-----------------------------------------------------------------*/
    server.SetupDB();

    /*-----------------------------------------------------------------*/
    /*                           QueryMake                             */
    /*-----------------------------------------------------------------*/
    int desired_index = 0;
    client.QueryMake(desired_index);

    /*-----------------------------------------------------------------*/
    /*                           QueryExpand                           */
    /*-----------------------------------------------------------------*/
    auto total_start = chrono::high_resolution_clock::now();
    auto start = chrono::high_resolution_clock::now();

    server.QueryExpand(client.qss);

    auto end = chrono::high_resolution_clock::now();
    auto expansion_time = (chrono::duration_cast<chrono::milliseconds>(end - start)).count();
    /*-----------------------------------------------------------------*/
    /*                           Process1                              */
    /*-----------------------------------------------------------------*/
    start = chrono::high_resolution_clock::now();

    server.Process1();

    end = chrono::high_resolution_clock::now();
    auto step1_time = (chrono::duration_cast<chrono::milliseconds>(end - start)).count();
    /*-----------------------------------------------------------------*/
    /*                           Process2                              */
    /*-----------------------------------------------------------------*/
    start = chrono::high_resolution_clock::now();
    server.Process2();

    end = chrono::high_resolution_clock::now();
    auto step2_time = (chrono::duration_cast<chrono::milliseconds>(end - start)).count();
    auto total_end = chrono::high_resolution_clock::now();
    auto total_time = (chrono::duration_cast<chrono::milliseconds>(total_end - total_start)).count();
    /*-----------------------------------------------------------------*/
    /*                           Reconstruct                           */
    /*-----------------------------------------------------------------*/
    auto decoded_response = client.Reconstruct(server.ss, num_multimap);

    /*-----------------------------------------------------------------*/
    /*                           Validate                              */
    /*-----------------------------------------------------------------*/
    bool incorrect_result = false;
    for (size_t db_i = 0; db_i < num_multimap; db_i++)
    {
        for (int i = 0; i < server.pir_obj_size / 4; i++)
        {
            if ((server.multimap_pir_db[db_i][desired_index][i] != decoded_response[db_i][i]) || (server.multimap_pir_db[db_i][desired_index][i + server.pir_obj_size / 4] != decoded_response[db_i][i + N / 2]))
            {
                incorrect_result = true;
                break;
            }
        }
    }
    if (incorrect_result)
    {
        std::cout << "Result is incorrect!" << std::endl
                  << std::endl;
    }
    else
    {
        std::cout << "Result is correct!" << std::endl
                  << std::endl;
        // print_report();
    }

    metrics["number_of_items"] = number_of_items;
    metrics["keyword_bitlength"] = key_size;
    metrics["item_Bytesize"] = obj_size;
    metrics["num_multimap"] = num_multimap;
    metrics["query_Bytesize"] = client.qss.str().size();
    metrics["response_Bytesize"] = server.ss.str().size();
    metrics["Query_expansion_time (ms)"] = expansion_time;
    metrics["Equality_check_time (ms)"] = step1_time;
    metrics["PIR_time (ms)"] = step2_time;
    metrics["total_time (ms)"] = total_time;
    metrics["correct"] = !incorrect_result;

    for (pair<string, uint64_t> metric : metrics)
    {
        std::cout << metric.first << ": " << metric.second << std::endl;
        // output_file << metric.first << ", " << metric.second << endl;
    }

    return 0;
}