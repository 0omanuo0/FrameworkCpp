
#include "server.hpp"
#include "tools/complementary_server_functions.hpp"
#include "jinjaTemplating/templating.h"

void HttpServer::_setup_server()
{
    this->loop_ = uvw::Loop::getDefault();
    this->server_ = loop_->resource<uvw::TCPHandle>();
    this->server_->bind(this->ip_, this->port_);

    // configureOpenSSL(this->ctx_, this->ssl_context_[0].c_str(), this->ssl_context_[1].c_str());
}

HttpServer::HttpServer(const std::string &ip, int port, const std::string ssl_context[])
    : workerPool_(4, taskQueue_)
{
    this->ip_ = ip;
    this->port_ = port;
    // ssl_context_[0] = ssl_context[0];
    // ssl_context_[1] = ssl_context[1];
    this->template_render = std::make_shared<Templating>();
    this->template_render->server = this;
    this->sessions_ = std::make_shared<SessionsManager>(uuid::generate_uuid_v4());
}

void HttpServer::_run_server()
{
    // ========== 1. Setup robust signal handling with sigaction ========== //
    struct sigaction sa;
    sa.sa_handler = SIG_IGN; // or a custom handler if you prefer
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGPIPE, &sa, nullptr) < 0)
    {
        this->logger_.error("Failed to ignore SIGPIPE via sigaction.");
    }

    // Optionally, handle SIGTERM gracefully to allow a clean shutdown:
    struct sigaction saTerm;
    saTerm.sa_handler = [](int)
    {
        // Here you could set a global atomic flag, or directly stop your server if accessible.
        // For demonstration, we do nothing. You might store `stopRequested = true;`
    };
    sigemptyset(&saTerm.sa_mask);
    saTerm.sa_flags = 0;
    sigaction(SIGTERM, &saTerm, nullptr);

    // ========== 2. Set up the server to accept new connections ========== //
    this->server_->on<uvw::ListenEvent>([this](const uvw::ListenEvent &, uvw::TCPHandle &srv)
    {
        auto client = srv.loop().resource<uvw::TCPHandle>();

        srv.accept(*client);
        client->read();

        // std::cout << "New client: " << client->peer().ip << std::endl;

        client->on<uvw::DataEvent>([this, client](const uvw::DataEvent &event, uvw::TCPHandle &)
        {
            std::string request(event.data.get(), event.length);
            this->_handle_request(request, client);
        });

        client->on<uvw::CloseEvent>([this, client](const uvw::CloseEvent &, uvw::TCPHandle &)
            { this->logger_.log("Client disconnected", client->peer().ip);});

        // Handle client errors
         client->on<uvw::ErrorEvent>([this](const uvw::ErrorEvent &event, uvw::TCPHandle &handle) {
            std::string errStr = event.what();
            if (errStr == "EPIPE" || errStr == "broken pipe") {
                // Not an error to kill the server; but log for debugging
                // this->logger_.debug("Broken pipe on client socket, ignoring.");
            } else {
                this->logger_.error("Client error: " + errStr);
                // Possibly close if it's a critical error
                if (handle.active()) {
                    handle.close();
                }
            }
        });
    });
    
    // Handle server errors
    this->server_->on<uvw::ErrorEvent>([this](const uvw::ErrorEvent &event, uvw::TCPHandle &)
                                       { this->logger_.error("Server error: " + std::string(event.what())); });

    // Start listening
    this->server_->listen(1024);
    this->logger_.log("Server is listening on " + this->ip_ + ":" + std::to_string(this->port_));

    // ========== 3. Run event loop with robust error handling ========== //
    try
    {
        // If you want a graceful shutdown, you might loop on run() until a stop flag is set
        this->loop_->run();
    }
    catch (const std::exception &e)
    {
        this->logger_.error("Critical error in event loop: " + std::string(e.what()));
    }
    catch (...)
    {
        this->logger_.error("Unknown error occurred in the event loop.");
    }

    // // ========== 4. Cleanup SSL resources carefully ========== //
    // // Make sure no other threads use this->ctx_ now.
    // SSL_CTX_free(this->ctx_);
    // this->ctx_ = nullptr;

    // // EVP_cleanup() may not be necessary on OpenSSL 1.1.0+,
    // // but if you're on older versions:
    // EVP_cleanup();
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
        // if (this->ctx_)
        // {
        //     SSL_CTX_free(this->ctx_);
        // }
    }
}

std::string HttpServer::Render(const std::string &route, nlohmann::json data)
{
    return this->template_render->Render(route, data);
}