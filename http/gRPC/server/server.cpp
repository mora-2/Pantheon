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
using grpc::ServerReader;
using grpc::ServerReaderWriter;
using grpc::Status;
using grpc::StatusCode;
using pantheon::CryptoKeys;
using pantheon::CryptoParams;
using pantheon::Info;
using pantheon::OneCiphertext;
using pantheon::PantheonInterface;
using pantheon::QueryStream;
using pantheon::ResponseStream;

class PantheonImpl final : public PantheonInterface::Service
{
private:
    std::mutex mu_;
    PIRServer *server;
    string keys_file_dir;
    vector<string> *db_keys;
    vector<string> *db_elems;

public:
    explicit PantheonImpl(PIRServer *_server, vector<string> *db_keys, vector<string> *db_elems, string &keys_file_dir) : server(_server), db_keys(db_keys), db_elems(db_elems), keys_file_dir(keys_file_dir) {}

    Status ReceiveParams(ServerContext *context, const Info *request, CryptoParams *response)
    {
        const string client_id = context->client_metadata().find("client_id")->second.data();

        response->set_parms_ss(server->parms_ss.str());
        std::cout << "[" << client_id << "] "
                  << "1.ReceiveParams finished." << std::endl;
        return Status::OK;
    }
    Status SendKeys(ServerContext *context, ServerReader<CryptoKeys> *reader, Info *response)
    {
        const string client_id = context->client_metadata().find("client_id")->second.data();
        std::stringstream ss;
        CryptoKeys keys_ss;

        int i = 0;
        while (reader->Read(&keys_ss))
        {
            ss << keys_ss.keys_ss();
        }
        // check stream status
        if (context->IsCancelled())
        {
            return Status::CANCELLED;
        }

        // save stream to file
        saveToBinaryFile(keys_file_dir + client_id + "/keys", ss.str());

        std::cout << "[" << client_id << "] "
                  << "2.SendKeys finished." << std::endl;
        return Status::OK;
    }
    Status SendOneCiphertext(ServerContext *context, const OneCiphertext *request, Info *response)
    {
        const string client_id = context->client_metadata().find("client_id")->second.data();
        std::stringstream ss(request->one_ct_ss());

        // save steram to file
        saveToBinaryFile(keys_file_dir + client_id + "/oneciphertext", ss.str());
        // check stream status
        if (context->IsCancelled())
        {
            return Status::CANCELLED;
        }

        std::cout << "[" << client_id << "] "
                  << "3.SendOneCiphertext finished." << std::endl;
        return Status::OK;
    }
    Status Query(ServerContext *context, const QueryStream *request, ResponseStream *response)
    {
        std::unique_lock<std::mutex> lock(this->mu_);
        const string client_id = context->client_metadata().find("client_id")->second.data();
        std::cout << "\r"
                  << "[" << client_id << "] "
                  << "4.Querying..." << std::flush;

        // loading client config
        std::string data = loadFromBinaryFile(keys_file_dir + client_id + "/keys");
        if (data == "")
        {
            Status status(StatusCode::UNAUTHENTICATED, "client haven't setup yet!");
            return status;
        }
        std::stringstream data_ss(data);
        server->SetupKeys(data_ss);
        data_ss.clear();
        data_ss.str("");

        data = loadFromBinaryFile(keys_file_dir + client_id + "/oneciphertext");
        if (data == "")
        {
            Status status(StatusCode::UNAUTHENTICATED, "client haven't setup yet!");
            return status;
        }
        data_ss.str(data);
        server->RecOneCiphertext(data_ss);
        server->SetupDB(*this->db_keys, *this->db_elems); // compact_pid
        // End of client config

        std::stringstream ss(request->qss());
        server->QueryExpand(ss);
        server->Process1();
        server->Process2(); // result to server->ss

        response->set_ss(server->ss.str());
        server->ss.clear();
        server->ss.str("");

        std::cout << "\r"
                  << "[" << client_id << "] "
                  << "4.Query finished." << std::endl;
        return Status::OK;
    }
};

void RunServer()
{
    /* keys_file_dir */
    string keys_file_dir = "/home/yuance/Work/Encryption/PIR/code/PIR/Pantheon/http/gRPC/server/data/";
    /* init PIRServer */
    uint64_t number_of_items = 1000;
    uint32_t key_size = 64;
    uint32_t obj_size = 32; // 256 bug?
    vector<string> db_keys = {"cat", "dog", "chik", "monkk"};
    vector<string> db_elems = {"cat", "dog", "fish", "dhsncjskfnxasdjwwwww"};

    PIRServer server(number_of_items, key_size, obj_size);
    PantheonImpl service(&server, &db_keys, &db_elems, keys_file_dir);

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