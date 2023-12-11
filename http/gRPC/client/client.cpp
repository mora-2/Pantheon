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

int main(int argc, char *argv[])
{
    /* client ID */
    Params input;
    ParamsParse(argc, argv, input);
    string clientID = input.clientID;
    string desired_key = input.q_key;

    if (clientID == "")
    {
        return -1;
    }

    uint32_t key_size = 64;
    uint32_t obj_size = 128;
    PIRClient client(key_size, obj_size);

    string target_str = "localhost:50051";
    PantheonClient rpc_client(grpc::CreateChannel(target_str, grpc::InsecureChannelCredentials()), &client, clientID);

    /*-----------------------------------------------------------------*/
    /*                           Load from file                        */
    /*-----------------------------------------------------------------*/
    string load_file_dir = "../data/" + clientID;
    client.SetupCrypto(load_file_dir);
    std::cout << "[" << clientID << "] "
              << "1.Crypto params loaded." << std::endl;

    /*-----------------------------------------------------------------*/
    /*                           QueryMake                             */
    /*-----------------------------------------------------------------*/
    client.QueryMake(desired_key);
    std::cout << "[" << clientID << "] "
              << "2.Query made." << std::endl;

    /*-----------------------------------------------------------------*/
    /*                           Answer                                */
    /*-----------------------------------------------------------------*/
    rpc_client.Query(client.qss);

    /*-----------------------------------------------------------------*/
    /*                           Reconstruct                           */
    /*-----------------------------------------------------------------*/
    auto decoded_response = client.ReconstructStr(rpc_client.answer_ss);
    std::cout << "[" << clientID << "] "
              << "4.Answer reconstructed: " << decoded_response << std::endl;

    return 0;
}