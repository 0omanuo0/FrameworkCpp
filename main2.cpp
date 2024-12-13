#include <openssl/ssl.h>
#include <openssl/err.h>
#include <uvw.hpp>
#include <memory>
#include <iostream>
#include <string>

class SSLClient
{
public:
    SSLClient(std::shared_ptr<uvw::TCPHandle> tcpHandle, SSL_CTX *sslCtx)
        : handle(std::move(tcpHandle)), ssl(SSL_new(sslCtx)), handshakeComplete(false)
    {
        readBIO = BIO_new(BIO_s_mem());
        writeBIO = BIO_new(BIO_s_mem());

        SSL_set_bio(ssl, readBIO, writeBIO);
        SSL_set_accept_state(ssl); // Set SSL to server mode
    }

    ~SSLClient()
    {
        SSL_free(ssl); // Frees SSL and associated BIOs
    }

    void handleData(const char *data, std::size_t length)
    {
        if (!writeToBIO(data, length))
        {
            std::cerr << "Failed to write to BIO" << std::endl;
            return;
        }

        if (!handshakeComplete)
        {
            performHandshake();
        }
        else
        {
            processDecryptedData();
        }

        flushPendingWrite();
    }

    void performHandshake()
    {
        int result = SSL_do_handshake(ssl);
        if (result == 1)
        {
            handshakeComplete = true;
            std::cout << "SSL handshake complete!" << std::endl;
        }
        else
        {
            int error = SSL_get_error(ssl, result);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
            {
                std::cerr << "SSL handshake failed" << std::endl;
            }
        }
    }

    void processDecryptedData()
    {
        char buffer[4096];
        int bytesRead = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytesRead > 0)
        {
            std::string data(buffer, bytesRead);
            std::cout << "Received data: " << data << std::endl;

            if (data == "exit\n")
            {
                handle->close();
            }
            else
            {
                sendHttpResponse();
            }
        }
        else
        {
            handleSSLError(bytesRead);
        }
    }

    void sendHttpResponse()
    {
        std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";
        SSL_write(ssl, response.c_str(), response.size());
    }

    void flushPendingWrite()
    {
        while (BIO_ctrl_pending(writeBIO) > 0)
        {
            char buffer[4096];
            int bytesToWrite = BIO_read(writeBIO, buffer, sizeof(buffer));
            if (bytesToWrite > 0)
            {
                auto writeBuffer = std::make_unique<char[]>(bytesToWrite);
                memcpy(writeBuffer.get(), buffer, bytesToWrite);
                handle->write(std::move(writeBuffer), bytesToWrite);
            }
        }
    }

    void close()
    {
        handle->close();
    }

private:
    std::shared_ptr<uvw::TCPHandle> handle;
    SSL *ssl;
    BIO *readBIO;
    BIO *writeBIO;
    bool handshakeComplete;

    bool writeToBIO(const char *data, std::size_t length)
    {
        return BIO_write(readBIO, data, length) > 0;
    }

    void handleSSLError(int result)
    {
        int error = SSL_get_error(ssl, result);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
        {
            std::cerr << "SSL read error" << std::endl;
            close();
        }
    }
};

void configureOpenSSL(SSL_CTX *&ctx)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Failed to create SSL context");
    }

    if (SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ctx))
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("SSL certificate or key error");
    }
}

void setupServerEvents(uvw::TCPHandle &serverHandle, SSL_CTX *ctx)
{
    serverHandle.on<uvw::ListenEvent>([ctx](const uvw::ListenEvent &, uvw::TCPHandle &server)
                                      {
        auto clientHandle = server.loop().resource<uvw::TCPHandle>();
        server.accept(*clientHandle);
        clientHandle->read();

        auto sslClient = std::make_shared<SSLClient>(clientHandle, ctx);

        clientHandle->on<uvw::DataEvent>([sslClient](const uvw::DataEvent &event, uvw::TCPHandle &handle) {
            sslClient->handleData(event.data.get(), event.length);
        });

        clientHandle->on<uvw::EndEvent>([sslClient](const uvw::EndEvent &, uvw::TCPHandle &handle) {
            std::cout << "Client disconnected" << std::endl;
            sslClient->close();
        });

        clientHandle->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &event, uvw::TCPHandle &) {
            std::cerr << "Client error: " << event.what() << std::endl;
        });

            std::cout << "New client connected!" << std::endl; 
    });

    serverHandle.on<uvw::ErrorEvent>([](const uvw::ErrorEvent &event, uvw::TCPHandle &)
                                     { std::cerr << "Server error: " << event.what() << std::endl; });
}

int main()
{
    SSL_CTX *sslCtx = nullptr;
    try
    {
        configureOpenSSL(sslCtx);

        auto loop = uvw::Loop::getDefault();
        auto server = loop->resource<uvw::TCPHandle>();

        server->bind("10.1.1.105", 4242);
        server->listen();

        setupServerEvents(*server, sslCtx);

        std::cout << "Server is listening on 10.1.1.105:4242" << std::endl;
        loop->run();

        SSL_CTX_free(sslCtx);
        EVP_cleanup();
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Error: " << ex.what() << std::endl;
        if (sslCtx)
        {
            SSL_CTX_free(sslCtx);
        }
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
