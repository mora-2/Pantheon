#include <iostream>
#include <grpc/grpc.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/channel.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/client_context.h>

#include "pantheon_pir.grpc.pb.h"
#include "PIRClient.h"
#include "globals.h"
#include "PantheonClient.h"

using namespace std;
using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReaderWriter;
using grpc::ClientWriter;
using grpc::Status;
using pantheon::CryptoKeys;
using pantheon::CryptoParams;
using pantheon::Info;
using pantheon::OneCiphertext;
using pantheon::PantheonInterface;
using pantheon::QueryStream;
using pantheon::ResponseStream;

uint32_t key_size = 64;
uint32_t obj_size = 128;

int main(int argc, char *argv[])
{
    string target_str = "219.245.186.51:50051";
    /* client ID */
    string clientID = ParamsParse(argc, argv);
    if (clientID == "")
    {
        return -1;
    }

    PIRClient client(key_size, obj_size);

    PantheonClient rpc_client(grpc::CreateChannel(target_str, grpc::InsecureChannelCredentials()), &client, clientID);

    /*-----------------------------------------------------------------*/
    /*                           CryptoParamSet                        */
    /*-----------------------------------------------------------------*/
    rpc_client.ReceiveParams();
    client.SetupCrypto(rpc_client.parms_ss);
    rpc_client.SendKeys(client.keys_ss);

    /*-----------------------------------------------------------------*/
    /*                           OneCiphertext                         */
    /*-----------------------------------------------------------------*/
    client.SetOneCiphertext();
    rpc_client.SendOneCiphertext(client.one_ct_ss);

    /*-----------------------------------------------------------------*/
    /*                           Save to file                          */
    /*-----------------------------------------------------------------*/
    string save_file_path = "../data/" + clientID + "/crypto_params";
    saveToBinaryFile(save_file_path, rpc_client.parms_ss.str());

    std::stringstream ss;
    client.secret_key.save(ss);
    save_file_path = "../data/" + clientID + "/crypto_secretkey";
    saveToBinaryFile(save_file_path, ss.str());

    return 0;
}