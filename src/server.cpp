
#include "server.hpp"
#include "tools/complementary_server_functions.hpp"
#include "jinjaTemplating/templating.h"




void HttpServer::_setup_server()
{
    this->loop_ = uvw::Loop::getDefault();
    this->server_ = loop_->resource<uvw::TCPHandle>();
    this->server_->bind(this->ip_, this->port_);

    configureOpenSSL(this->ctx_, this->ssl_context_[0].c_str(), this->ssl_context_[1].c_str());
}

HttpServer::HttpServer(const std::string &ip, int port, const std::string ssl_context[])
    : workerPool_(4, taskQueue_)
{
    this->ip_ = ip;
    this->port_ = port;
    ssl_context_[0] = ssl_context[0];
    ssl_context_[1] = ssl_context[1];
    this->template_render = std::make_shared<Templating>();
    this->template_render->server = this;
    this->sessions_ = std::make_shared<SessionsManager>(uuid::generate_uuid_v4());
}




void HttpServer::_run_server()
{
    this->server_->on<uvw::ListenEvent>([this](const uvw::ListenEvent &, uvw::TCPHandle &srv)
                                        {
        auto client = srv.loop().resource<uvw::TCPHandle>();
        
        srv.accept(*client);
        client->read();

        auto sslClient = std::make_shared<SSLClient>(client, this->ctx_);

        // std::cout << "New client: " << client->peer().ip << std::endl;


        sslClient->onData([sslClient, this, client ](const char *data, std::size_t length) {
            std::string request(data, length);
            this->_handle_request(request, sslClient);
        });

        sslClient->onClose([this, client]() {
            this->logger_.log("Client disconnected", client->peer().ip);
        });

        client->on<uvw::ErrorEvent>([this](const uvw::ErrorEvent &event, uvw::TCPHandle &)
            { this->logger_.error("Client error: " + std::string(event.what())); }); 
    });

    this->server_->on<uvw::ErrorEvent>([this](const uvw::ErrorEvent &event, uvw::TCPHandle &)
                                       { this->logger_.error("Server error: " + std::string(event.what())); });

    //
    this->server_->listen(128);
    this->logger_.log("Server is listening on " + this->ip_ + ":" + std::to_string(this->port_));
    // handle broken pipe
    try
    {
        this->loop_->run();
    }
    catch (const std::exception &e)
    {
        this->logger_.error("Error: " + std::string(e.what()));
    }

    SSL_CTX_free(this->ctx_);
    EVP_cleanup();
}

void HttpServer::run()
{
    try
    {
        this->_setup_server();
    }
    catch (const std::exception &ex)
    {
        this->logger_.error("Error: " + std::string(ex.what()));
    }

    try
    {
        this->_run_server();
    }
    catch (const std::exception &ex)
    {
        this->logger_.error("Error: " + std::string(ex.what()));
        if (this->ctx_)
        {
            SSL_CTX_free(this->ctx_);
        }
    }
}

std::string HttpServer::Render(const std::string &route, nlohmann::json data)
{
    return this->template_render->Render(route, data);
}