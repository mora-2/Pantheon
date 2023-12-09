#include <iostream>
#include <grpc/grpc.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/channel.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/client_context.h>

#include "pantheon_pir.grpc.pb.h"
#include "PIRClient.h"
#include "globals.h"

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

class PantheonClient
{
public:
    std::stringstream parms_ss;
    std::stringstream answer_ss;

private:
    PIRClient *client;
    std::unique_ptr<PantheonInterface::Stub> stub_;

public:
    explicit PantheonClient(std::shared_ptr<Channel> channel, PIRClient *client) : stub_(PantheonInterface::NewStub(channel)), client(client) {}

    void ReceiveParams()
    {
        Info request;
        CryptoParams reply;
        ClientContext context;
        Status status = stub_->ReceiveParams(&context, request, &reply);
        if (status.ok())
        {
            this->parms_ss << reply.parms_ss();
            // return reply.message();
            return;
        }
        else
        {
            std::cout << "RPC failed" << std::endl;
            std::cout << status.error_code() << ": " << status.error_message()
                      << std::endl;
            return;
        }
    }

    void SendKeys(std::stringstream &keys_ss)
    {
        CryptoKeys request;
        // request.set_keys_ss(keys_ss.str());
        Info reply;
        ClientContext context;

        std::unique_ptr<ClientWriter<CryptoKeys>> writer(stub_->SendKeys(&context, &reply));

        for (size_t i = 0; i < keys_ss.str().size(); i += GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH - 100)
        {
            request.set_keys_ss(keys_ss.str().substr(i, GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH - 100));
            if (!writer->Write(request))
            {
                // Broken stream.
                break;
            }
        }
        writer->WritesDone();

        Status status = writer->Finish();
        if (status.ok())
        {
            // return reply.message();
            return;
        }
        else
        {
            std::cout << "RPC failed" << std::endl;
            std::cout << status.error_code() << ": " << status.error_message()
                      << std::endl;
            return;
        }
    }

    void SendOneCiphertext(std::stringstream &one_ct_ss)
    {
        OneCiphertext request;
        request.set_one_ct_ss(one_ct_ss.str());
        Info reply;
        ClientContext context;
        Status status = stub_->SendOneCiphertext(&context, request, &reply);
        if (status.ok())
        {
            // return reply.message();
            return;
        }
        else
        {
            std::cout << "RPC failed" << std::endl;
            std::cout << status.error_code() << ": " << status.error_message()
                      << std::endl;
            return;
        }
    }

    void Query(std::stringstream &qss)
    {
        QueryStream request;
        request.set_qss(qss.str());
        ResponseStream reply;
        ClientContext context;
        Status status = stub_->Query(&context, request, &reply);
        if (status.ok())
        {
            this->answer_ss << reply.ss();
            // return reply.message();
            return;
        }
        else
        {
            std::cout << "RPC failed" << std::endl;
            std::cout << status.error_code() << ": " << status.error_message()
                      << std::endl;
            return;
        }
    }
};

int main(int argc, char *argv[])
{
    uint32_t key_size = 64;
    uint32_t obj_size = 128;
    PIRClient client(key_size, obj_size);

    string target_str = "localhost:50051";
    PantheonClient rpc_client(grpc::CreateChannel(target_str, grpc::InsecureChannelCredentials()), &client);

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
    /*                           QueryMake                             */
    /*-----------------------------------------------------------------*/
    int desired_index = 0;
    client.QueryMake(desired_index);

    /*-----------------------------------------------------------------*/
    /*                           Answer                                */
    /*-----------------------------------------------------------------*/
    rpc_client.Query(client.qss);

    /*-----------------------------------------------------------------*/
    /*                           Reconstruct                           */
    /*-----------------------------------------------------------------*/
    auto decoded_response = client.Reconstruct(rpc_client.answer_ss);

    return 0;
}