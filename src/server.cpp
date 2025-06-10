
#include "server.hpp"
#include "tools/complementary_server_functions.hpp"
#include "jinjaTemplating/templating.h"

void HttpServer::_setup_server()
{
    this->loop_ = uvw::Loop::getDefault();
    this->server_ = loop_->resource<uvw::TCPHandle>();
    this->server_->bind(this->ip_, this->port_);
    this->sessions_ = std::make_shared<SessionsManager>(uuid::generate_uuid_v4());
    if (this->ssl_enabled_)
    {
        SSL_CTX *sslCtx = TlsServer::init(this->loop_, this->ssl_context_[0], this->ssl_context_[1]);
        this->tlsServer_ = std::make_shared<TlsServer>(this->loop_, sslCtx);
    }
    this->template_render = std::make_shared<Templating>();
    this->template_render->server = this;
}

HttpServer::HttpServer(const std::string &ip, int port)
    : workerPool_(4, taskQueue_)
{
    this->ip_ = ip;
    this->port_ = port;
}

HttpServer::HttpServer(const std::string &ip, int port, const std::string ssl_context[])
    : workerPool_(4, taskQueue_)
{
    this->ip_ = ip;
    this->port_ = port;
    this->ssl_context_[0] = ssl_context[0];
    this->ssl_context_[1] = ssl_context[1];
    this->ssl_enabled_ = !this->ssl_context_[0].empty() && !this->ssl_context_[1].empty();
}

void HttpServer::_run_server()
{

    // ========== 2. Set up the server to accept new connections ========== //
    this->server_->on<uvw::ListenEvent>([this](const uvw::ListenEvent &, uvw::TCPHandle &srv)
                                        {
        auto client = srv.loop().resource<uvw::TCPHandle>();

        srv.accept(*client);
        client->read();

        server_types::HttpClient client_data = {
            .client = client,
            .keep_alive = true,
            .n_requests = 0,
            .timeout = srv.loop().resource<uvw::TimerHandle>()
        };

        client_data.timeout->start(uvw::TimerHandle::Time{5000}, uvw::TimerHandle::Time{0});
        client_data.timeout->on<uvw::TimerEvent>([client_data](const uvw::TimerEvent &, uvw::TimerHandle &)
        {
            client_data.client->close();
        });

        this->clients[client.get()] = client_data;


        // std::cout << "New client: " << client->peer().ip << std::endl;

        client->on<uvw::DataEvent>([this, client](const uvw::DataEvent &event, uvw::TCPHandle &)
        {
            // reset timeout
            this->clients[client.get()].timeout->stop();
            this->clients[client.get()].timeout->start(uvw::TimerHandle::Time{5000}, uvw::TimerHandle::Time{0});

            std::shared_ptr<HttpConnection> conn = std::make_shared<HttpConnection>(client);

            std::string request(event.data.get(), event.length);
            this->_handle_request(request, conn);

            this->clients[client.get()].n_requests++;
            if (this->clients[client.get()].n_requests > 100)
            {
                this->clients[client.get()].client->close();
            }
        });

        client->on<uvw::CloseEvent>([this, client](const uvw::CloseEvent &, uvw::TCPHandle &)
        { 
            if (this->clients.find(client.get()) != this->clients.end())
                this->clients.erase(client.get());

            this->logger_.log("Client disconnected", client->peer().ip);
            
        });

        // Handle client errors
         client->on<uvw::ErrorEvent>([this, client](const uvw::ErrorEvent &event, uvw::TCPHandle &handle) {
            std::string errStr = event.what();
            if (errStr == "EPIPE" || errStr == "broken pipe") {
                // Not an error to kill the server; but log for debugging
                // this->logger_.debug("Broken pipe on client socket, ignoring.");
            } else {
                this->logger_.error("Client error: " + errStr);

                if (this->clients.find(client.get()) != this->clients.end())
                    this->clients.erase(client.get());

                // Possibly close if it's a critical error
                if (handle.active()) {
                    handle.close();
                }
            }
        }); });

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
}

void HttpServer::_run_server_ssl()
{

    // ========== 2. Set up the server to accept new connections ========== //
    server_->on<uvw::ListenEvent>([http_ = this, self = this->tlsServer_](const uvw::ListenEvent &, uvw::TCPHandle &srv)
                                  {
        auto client = srv.loop().resource<uvw::TCPHandle>();
        srv.accept(*client);

        server_types::HttpClient client_data = {
            .client = client,
            .keep_alive = true,
            .n_requests = 0,
            .timeout = srv.loop().resource<uvw::TimerHandle>()
        };

        http_->clients[client.get()] = client_data;

        auto tlsConn = TlsConnection::createClient(client, self->sslCtx_);

        tlsConn
        ->on<TlsServer::TlsErrorEvent>(
            [http_](const TlsServer::TlsErrorEvent &err, TlsConnection &self)
            {
                http_->logger_.warning("TLS-error "
                            + std::to_string(err.code) + " – "
                            + err.message);
            });

        client->read();

        client_data.timeout->start(uvw::TimerHandle::Time{5000}, uvw::TimerHandle::Time{0});
        client_data.timeout->on<uvw::TimerEvent>(
            [client_data, self, weakConn = std::weak_ptr<TlsConnection>(tlsConn)]
            (const uvw::TimerEvent &, uvw::TimerHandle &)
            {
                // close the connection ssl
                auto strong = weakConn.lock();
                if (strong) 
                    self->removeConnection(strong);
                
                strong->close();
            });


        tlsConn->setOnClose(
            [http_, client, self, weakConn=std::weak_ptr<TlsConnection>(tlsConn)]
            (int err) 
            {
                http_->logger_.log("Client disconnected", client->peer().ip);
                if(auto strong = weakConn.lock()) {
                    self->removeConnection(strong);
                }
                if (http_->clients.find(client.get()) != http_->clients.end())
                    http_->clients.erase(client.get());
            });

        // Example onRead
        tlsConn->setOnRead(
            [http_, client, tlsConn, self]
            (const char* data, std::size_t len) 
            {
                // reset timeout
                http_->clients[client.get()].timeout->stop();
                http_->clients[client.get()].timeout->start(uvw::TimerHandle::Time{5000}, uvw::TimerHandle::Time{0});

                std::string request(data, len);

                // Create a new HttpConnection instance
                std::shared_ptr<HttpConnection> conn = std::make_shared<HttpConnection>(client, tlsConn);

                // Handle the request
                http_->_handle_request(request, conn);

                http_->clients[client.get()].n_requests++;
                if (http_->clients[client.get()].n_requests > 100)
                {
                    self->removeConnection(tlsConn);
                    client->close();
                    return;
                }

            });

        client->on<uvw::ErrorEvent>(
            [http_, client]
            (const uvw::ErrorEvent &event, uvw::TCPHandle &handle)
            {
                std::string errStr = event.what();
                if (errStr == "EPIPE" || errStr == "broken pipe") {
                    // Not an error to kill the server; but log for debugging
                    http_->logger_.debug("Broken pipe on client socket, ignoring.");
                } else {
                    http_->logger_.error("Client error: " + errStr);

                    // if (http_->clients.find(client.get()) != http_->clients.end())
                    //     http_->clients.erase(client.get());

                    // Possibly close if it's a critical error
                    // if (handle.active()) {
                    //     handle.close();
                    // }
                }
            }); 
    });

    // Handle server errors
    this
        ->server_
        ->on<uvw::ErrorEvent>(
            [this]
            (const uvw::ErrorEvent &event, uvw::TCPHandle &)
            { this->logger_.error("Server error: " + std::string(event.what())); });

    // Start listening
    this->server_->listen(1024);
    this->logger_.log("Server is listening on https://" + this->ip_ + ":" + std::to_string(this->port_));

    // Prepare handle to flush connections each loop iteration
    this->tlsServer_->prepare_ = loop_->resource<uvw::PrepareHandle>();
    this
        ->tlsServer_
        ->prepare_
        ->on<uvw::PrepareEvent>(
            [self = this->tlsServer_]
            (const uvw::PrepareEvent &, uvw::PrepareHandle &)
            { self->flushAllConnections(); });
            
    this->tlsServer_->prepare_->start();

    // ========== 3. Run event loop with robust error handling ========== //
    try
    {
        // If you want a graceful shutdown, you might loop on run() until a stop flag is set
        this->loop_->run(); // MAYBE: while (!stop_) loop_->run<uvw::Loop::Mode::ONCE>();
    }
    catch (const std::exception &e)
    {
        this->logger_.error("Critical error in event loop: " + std::string(e.what()));
    }
    catch (...)
    {
        this->logger_.error("Unknown error occurred in the event loop.");
    }
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

    try
    {
        if (this->ssl_enabled_)
            this->_run_server_ssl();
        else
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