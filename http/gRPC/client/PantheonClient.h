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
    string client_id;

private:
    PIRClient *client;
    std::unique_ptr<PantheonInterface::Stub> stub_;

public:
    explicit PantheonClient(std::shared_ptr<Channel> channel, PIRClient *client, string &client_id) : stub_(PantheonInterface::NewStub(channel)), client(client), client_id(client_id) {}

    void ReceiveParams()
    {
        Info request;
        CryptoParams reply;
        ClientContext context;
        context.AddMetadata("client_id", this->client_id);

        Status status = stub_->ReceiveParams(&context, request, &reply);
        if (status.ok())
        {
            this->parms_ss << reply.parms_ss();
            std::cout << "[" << this->client_id << "] "
                      << "1.ReceiveParams." << std::endl;
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
        std::cout << "\r"
                  << "[" << this->client_id << "] "
                  << "2.Sending keys..." << std::flush;
        CryptoKeys request;
        // request.set_keys_ss(keys_ss.str());
        Info reply;
        ClientContext context;
        context.AddMetadata("client_id", this->client_id);

        std::unique_ptr<ClientWriter<CryptoKeys>> writer(stub_->SendKeys(&context, &reply));

        for (size_t i = 0; i < keys_ss.str().size(); i += GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH - 100)
        {
            request.set_keys_ss(keys_ss.str().substr(i, GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH - 100));
            if (!writer->Write(request))
            {
                // Broken stream.
                break;
            }

            std::cout << "\r"
                      << "[" << this->client_id << "] "
                      << "Sent Msgs Count: " << i / (GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH - 100) << "/" << keys_ss.str().size() / (GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH - 100) << std::flush;
        }

        writer->WritesDone();

        Status status = writer->Finish();
        if (status.ok())
        {
            std::cout << "\r"
                      << "[" << this->client_id << "] "
                      << "2.Keys sent.      " << std::endl;
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
        context.AddMetadata("client_id", this->client_id);

        Status status = stub_->SendOneCiphertext(&context, request, &reply);
        if (status.ok())
        {
            std::cout << "[" << this->client_id << "] "
                      << "3.OneCiphertext sent." << std::endl;
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
        std::cout << "\r"
                  << "[" << this->client_id << "] "
                  << "3.Answering from server..." << std::flush;
        QueryStream request;
        request.set_qss(qss.str());
        ResponseStream reply;
        ClientContext context;
        context.AddMetadata("client_id", this->client_id);

        Status status = stub_->Query(&context, request, &reply);
        if (status.ok())
        {
            this->answer_ss << reply.ss();
            std::cout << "\r"
                      << "[" << this->client_id << "] "
                      << "3.Answer received.        " << std::endl;
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

struct Params
{
    string clientID;
    string q_key;
};

string ParamsParse(int argc, char *argv[])
{
    int opt;
    char *id = NULL;
    const char *optstring = "i:";
    while ((opt = getopt(argc, argv, optstring)) != -1)
    {
        switch (opt)
        {
        case 'i':
            id = optarg;
            break;
        case '?':
            return "";
            break;
        default:
            fprintf(stderr, "Usage: %s -i clientID\n", argv[0]);
            return "";
        }
    }

    if (id == NULL)
    {
        fprintf(stderr, "You must specify id.\n");
        fprintf(stderr, "Usage: %s -i clientID\n", argv[0]);
        return "";
    }

    return string(id);
}

void ParamsParse(int argc, char *argv[], Params &params)
{
    int opt;
    char *id = NULL;
    char *q_key = NULL;
    const char *optstring = "i:q:";
    while ((opt = getopt(argc, argv, optstring)) != -1)
    {
        switch (opt)
        {
        case 'i':
            id = optarg;
            break;
        case 'q':
            q_key = optarg;
            break;
        case '?':
            break;
        default:
            fprintf(stderr, "Usage: %s -i clientID -q query_key\n", argv[0]);
        }
    }

    if (id == NULL || q_key == NULL)
    {
        fprintf(stderr, "You must specify arguments.\n");
        fprintf(stderr, "Usage: %s -i clientID -q query_key\n", argv[0]);
    }

    params.clientID = id;
    params.q_key = q_key;
}
