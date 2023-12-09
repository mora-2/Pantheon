#include <iostream>
#include "PIRServer.h"
#include "PIRClient.h"
#include "globals.h"

using namespace std;

int main(int argc, char *argv[])
{
    uint64_t number_of_items = 10000;
    uint32_t key_size = 64;
    uint32_t obj_size = 32;
    vector<string> keydb={"cat","dog","chik","monkk"};
    vector<std::string> elems={"cat","dog","fish","dhsncjskfnxasdjwwwww"};
    string desired_key = "monkk";
    int desired_index = 3;
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
    server.SetupDB(keydb,elems);

    /*-----------------------------------------------------------------*/
    /*                           QueryMake                             */
    /*-----------------------------------------------------------------*/
    client.QueryMake(desired_key);

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
    client.Reconstruct(server.ss);

    /*-----------------------------------------------------------------*/
    /*                           showresult                            */
    /*-----------------------------------------------------------------*/
    client.showresult();
    return 0;
}