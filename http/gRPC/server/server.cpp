#include <iostream>
#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include "pantheon_pir.grpc.pb.h"
#include "PIRServer.h"
#include "globals.h"

using namespace std;
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using pantheon::CryptoKeys;
using pantheon::CryptoParams;
using pantheon::Info;
using pantheon::OneCiphertext;
using pantheon::PantheonInterface;
using pantheon::QueryStream;
using pantheon::ResponseStream;

class PantheonImpl final : public PantheonInterface::Service
{
public:
    explicit PantheonImpl(PIRServer *_server) : server(_server) {}

    Status ReceiveParams(ServerContext *context, const Info *request, CryptoParams *response)
    {
        response->set_parms_ss(server->parms_ss.str());
        return Status::OK;
    }
    Status SendKeys(ServerContext *context, const CryptoKeys *request, Info *response)
    {
        std::stringstream ss(request->keys_ss());
        server->SetupKeys(ss);
        return Status::OK;
    }
    Status SendOneCiphertext(ServerContext *context, const OneCiphertext *request, Info *response)
    {
        std::stringstream ss(request->one_ct_ss());
        server->RecOneCiphertext(ss);
        server->SetupDB(); // compact_pid
        return Status::OK;
    }
    Status Query(ServerContext *context, const QueryStream *request, ResponseStream *response)
    {
        std::unique_lock<std::mutex> lock(this->mu_);
        std::stringstream ss(request->qss());
        server->QueryExpand(ss);
        server->Process1();
        server->Process2();

        response->set_ss(server->ss.str());
        return Status::OK;
    }

private:
    std::mutex mu_;
    PIRServer *server;
};

void RunServer()
{
    /* init PIRServer */
    uint64_t number_of_items = 10000;
    uint32_t key_size = 64;
    uint32_t obj_size = 128;
    PIRServer server(number_of_items, key_size, obj_size);
    PantheonImpl service(&server);

    /* server pre-process */
    server.SetupCryptoParams();

    /* gRPC build */
    ServerBuilder builder;
    std::string server_address("0.0.0.0:50051");
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::unique_ptr<::grpc::Server> rpc_server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;

    /* wait for call */
    rpc_server->Wait();
}

int main(int argc, char *argv[])
{
    RunServer();
    return 0;
}