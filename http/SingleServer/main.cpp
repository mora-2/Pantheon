#include <iostream>
#include "PIRServer.h"
#include "PIRClient.h"
#include "globals.h"
using namespace std;

int main(int argc, char *argv[])
{
    uint64_t number_of_items = 10000;
    uint32_t key_size = 64;
    uint32_t obj_size = 128;

    PIRServer server(number_of_items, key_size, obj_size);
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
    server.QueryExpand(client.qss);

    /*-----------------------------------------------------------------*/
    /*                           Process1                              */
    /*-----------------------------------------------------------------*/
    server.Process1();

    /*-----------------------------------------------------------------*/
    /*                           Process2                              */
    /*-----------------------------------------------------------------*/
    server.Process2();

    /*-----------------------------------------------------------------*/
    /*                           Reconstruct                           */
    /*-----------------------------------------------------------------*/
    auto decoded_response = client.Reconstruct(server.ss);

    /*-----------------------------------------------------------------*/
    /*                           Validate                              */
    /*-----------------------------------------------------------------*/
    bool incorrect_result = false;
    for (int i = 0; i < server.pir_obj_size / 4; i++)
    {
        if ((server.pir_db[desired_index][i] != decoded_response[i]) || (server.pir_db[desired_index][i + server.pir_obj_size / 4] != decoded_response[i + N / 2]))
        {
            incorrect_result = true;
            break;
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
    return 0;
}