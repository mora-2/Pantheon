#include <iostream>
#include <unistd.h>
#include <fstream>
#include <map>
#include "PIRServer.h"
#include "PIRClient.h"
#include "globals.h"
#include <chrono>
using namespace std;

int main(int argc, char *argv[])
{
#pragma region args
    double alpha;
    size_t max_value;
    uint64_t total_samples;
    uint32_t key_size;
    uint32_t obj_size;
    string result_filepath;
    int option;
    const char *optstring = "a:n:m:k:s:w:";
    while ((option = getopt(argc, argv, optstring)) != -1)
    {
        switch (option)
        {
        case 'a':
            alpha = stod(optarg);
            break;
        case 'n':
            total_samples = stoi(optarg);
            break;
        case 'm':
            max_value = stoi(optarg);
            break;
        case 'k':
            key_size = stoi(optarg);
            break;
        case 's':
            obj_size = stoi(optarg);
            break;
        case 'w':
            result_filepath = optarg;
            break;
        case '?':
            cout << "error optopt: " << optopt << endl;
            cout << "error opterr: " << opterr << endl;
            return 1;
        }
    }
    if (!alpha)
    {
        cout << "Missing -a\n";
        return 0;
    }
    if (!total_samples)
    {
        cout << "Missing -n\n";
        return 0;
    }
    if (!max_value)
    {
        cout << "Missing -m\n";
        return 0;
    }
    if (!key_size)
    {
        cout << "Missing -k\n";
        return 0;
    }
    if (!obj_size)
    {
        cout << "Missing -s\n";
        return 0;
    }
    if (result_filepath == "")
    {
        cout << "Missing -w\n";
        return 0;
    }
#pragma endregion args

    map<string, double> metrics;
    uint64_t number_of_items = total_samples;
    PIRServer::ParetoParams pareto(alpha, max_value, total_samples);
    PIRServer server(pareto, key_size, obj_size);
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
    cout << "[2. SetupDB] Finished." << endl;

    /*-----------------------------------------------------------------*/
    /*                           QueryMake                             */
    /*-----------------------------------------------------------------*/
    int desired_index = 1;
    client.QueryMake(desired_index);

    /*-----------------------------------------------------------------*/
    /*                           QueryExpand                           */
    /*-----------------------------------------------------------------*/
    auto total_start = chrono::high_resolution_clock::now();
    auto start = chrono::high_resolution_clock::now();

    server.QueryExpand(client.qss);

    auto end = chrono::high_resolution_clock::now();
    auto expansion_time = (chrono::duration_cast<chrono::milliseconds>(end - start)).count();
    cout << "[3. QueryExpand] Elapsed(ms): " << expansion_time << endl;
    /*-----------------------------------------------------------------*/
    /*                           Process1                              */
    /*-----------------------------------------------------------------*/
    start = chrono::high_resolution_clock::now();

    server.Process1();

    end = chrono::high_resolution_clock::now();
    auto step1_time = (chrono::duration_cast<chrono::milliseconds>(end - start)).count();
    cout << "[4. Equality Check] Process1(ms): " << step1_time << endl;
    /*-----------------------------------------------------------------*/
    /*                           Process2                              */
    /*-----------------------------------------------------------------*/
    start = chrono::high_resolution_clock::now();
    server.Process2();

    end = chrono::high_resolution_clock::now();
    auto step2_time = (chrono::duration_cast<chrono::milliseconds>(end - start)).count();
    cout << "[5. PIR] Process2(ms): " << step2_time << endl;
    auto total_end = chrono::high_resolution_clock::now();
    auto total_time = (chrono::duration_cast<chrono::milliseconds>(total_end - total_start)).count();
    /*-----------------------------------------------------------------*/
    /*                           Reconstruct                           */
    /*-----------------------------------------------------------------*/
    vector<uint32_t> db_index;
    server.DBIndexSearch(desired_index, db_index);
    auto decoded_response = client.Reconstruct(server.ss, server.num_multimap, db_index);

    /*-----------------------------------------------------------------*/
    /*                           Validate                              */
    /*-----------------------------------------------------------------*/

    bool incorrect_result = false;
    for (size_t db_i = 0; db_i < server.num_multimap; db_i++)
    {
        bool flag = true;
        for (int i = 0; i < server.pir_obj_size / 4; i++)
        {
            if (db_index[db_i] == PIRServer::INVALID_INDEX)
            {
                if ((0 != decoded_response[db_i][i]) || (0 != decoded_response[db_i][i + N / 2]))
                {
                    incorrect_result = true;

                    flag = false;
                    // break;
                }
            }
            else
            {
                if ((server.multimap_pir_db[db_i][db_index[db_i]][i] != decoded_response[db_i][i]) || (server.multimap_pir_db[db_i][db_index[db_i]][i + server.pir_obj_size / 4] != decoded_response[db_i][i + N / 2]))
                {
                    incorrect_result = true;
                    flag = false;
                    // break;
                }
            }
            if (flag == false)
            {
                cout << "[" << db_i << "]  pir_db: " << server.multimap_pir_db[db_i][db_index[db_i]][i] << "  " << server.multimap_pir_db[db_i][db_index[db_i]][i + server.pir_obj_size / 4] << endl;
                cout << "[" << db_i << "]response: " << decoded_response[db_i][i] << "  " << decoded_response[db_i][i + N / 2] << endl;
            }
            else
            {
                cout << "[" << db_i << "]response: " << decoded_response[db_i][i] << "  " << decoded_response[db_i][i + N / 2] << endl;
            }
        }
        if (flag == false)
        {
            cout << "db_i: " << db_i << "  InCorrect!" << endl;
        }
        else
        {
            cout << "db_i: " << db_i << "  Correct!" << endl;
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

    metrics["pareto_alpha"] = alpha;
    metrics["pareto_max_value"] = max_value;
    metrics["number_of_items"] = total_samples;
    metrics["number_true_samples"] = server.number_of_items_total;
    metrics["num_multimap"] = server.num_multimap;
    metrics["keyword_bitlength"] = key_size;
    metrics["item_Bytesize"] = obj_size;
    metrics["query_Bytesize"] = client.qss.str().size();
    metrics["response_Bytesize"] = server.ss.str().size();
    metrics["Query_expansion_time (ms)"] = expansion_time;
    metrics["Equality_check_time (ms)"] = step1_time;
    metrics["PIR_time (ms)"] = step2_time;
    metrics["total_time (ms)"] = total_time;
    metrics["correct"] = !incorrect_result;

    std::ofstream output_file(result_filepath, std::ios::app);

    if (output_file.is_open())
    {
        output_file.seekp(0, std::ios::end);
        if (output_file.tellp() == 0)
        {
            for (pair<string, uint64_t> metric : metrics)
            {
                output_file << metric.first << ", ";
            }
            output_file << endl;
        }

        for (pair<string, uint64_t> metric : metrics)
        {
            output_file << metric.second << ", ";
        }
        output_file << endl;

        output_file.close();
        std::cout << "Results appended to file." << std::endl;
    }
    else
    {
        std::cerr << "Failed to open file." << std::endl;
        return 1;
    }

    return 0;
}