#ifndef SERVER_SSL_HPP
#define SERVER_SSL_HPP

#include <uvw.hpp>
#include <memory>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>
#include <functional>
#include <iostream>

class SSLClient
{
public:
    using DataCallback = std::function<void(const char *data, std::size_t length)>;
    using CloseCallback = std::function<void()>;

    SSLClient(std::shared_ptr<uvw::TCPHandle> tcpHandle, SSL_CTX *sslCtx)
        : handle(std::move(tcpHandle)), ssl(SSL_new(sslCtx)), handshakeComplete(false)
    {
        readBIO = BIO_new(BIO_s_mem()); // BIO is the abstraction for I/O operations in OpenSSL
        writeBIO = BIO_new(BIO_s_mem());

        SSL_set_bio(ssl, readBIO, writeBIO);
        SSL_set_accept_state(ssl); // Set SSL to server mode

        setupEvents();
    }

    ~SSLClient()
    {
        SSL_free(ssl); // Frees SSL and associated BIOs
    }

    void onData(const DataCallback &callback)
    {
        dataCallback = callback;
    }

    void onClose(const CloseCallback &callback)
    {
        closeCallback = callback;
    }

    void write(std::unique_ptr<char[]> data, std::size_t length)
    {
        if(!ssl)
            return;
        
        if (SSL_write(ssl, data.get(), static_cast<int>(length)) > 0)
        {
            flushPendingWrite();
        }
        else
        {
            std::cerr << "SSL write error: " << SSL_get_error(ssl, -1) << std::endl;
            handle->close();
        }
    }

private:
    std::shared_ptr<uvw::TCPHandle> handle;
    SSL *ssl;
    BIO *readBIO;
    BIO *writeBIO;
    bool handshakeComplete;

    DataCallback dataCallback;
    CloseCallback closeCallback;

    void setupEvents()
    {
        handle->on<uvw::DataEvent>([this](const uvw::DataEvent &event, uvw::TCPHandle &)
                                   { handleData(event.data.get(), event.length); });

        handle->on<uvw::EndEvent>([this](const uvw::EndEvent &, uvw::TCPHandle &)
                                  { close(); });

        handle->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &event, uvw::TCPHandle &)
                                    { std::cerr << "TCP Error: " << event.what() << std::endl; });
    }

    void handleData(const char *data, std::size_t length)
    {
        // std::cout << "Received raw data (length: " << length << "): " << std::string(data, length) << std::endl;
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
            // std::cout << "SSL handshake complete!" << std::endl;
        }
        else
        {

            int error = SSL_get_error(ssl, result);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
            {
                std::cerr << "SSL handshake failed" << std::endl;
                close();
            }
            else if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
            {
                // std::cout << "SSL handshake in progress" << std::endl;
                return;
            }
            else
            {
                std::cerr << "SSL handshake failed with error: " << error << std::endl;
                ERR_print_errors_fp(stderr); // Imprimir detalles del error
                close();
            }
        }
    }

    void processDecryptedData()
    {
        char buffer[65536]; // 64KB buffer
        int bytesRead = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytesRead > 0)
        {
            if (dataCallback)
                dataCallback(buffer, static_cast<std::size_t>(bytesRead));
        }
        else if (bytesRead == 0)
            close();
        else
            handleSSLError(bytesRead);
    }

    void flushPendingWrite()
    {
        // Check that ssl and writeBIO are still valid
        if (!ssl || !writeBIO)
            return;

        while (BIO_ctrl_pending(writeBIO) > 0)
        {
            char buffer[65536]; // 64KB buffer
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
        if (closeCallback)
        {
            closeCallback();
        }

        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }

        handle->close();
    }

    bool writeToBIO(const char *data, std::size_t length)
    {
        return BIO_write(readBIO, data, static_cast<int>(length)) > 0;
    }

    void handleSSLError(int result)
    {
        int error = SSL_get_error(ssl, result);
        if (error == SSL_ERROR_ZERO_RETURN)
        {
            close();
        }
        else if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
        {
            std::cerr << "SSL read error" << std::endl;
            close();
        }
    }
};

inline void configureOpenSSL(SSL_CTX *&ctx, const char *certFile, const char *keyFile)
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

    if (SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ctx))
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("SSL certificate or key error");
    }
}

#endif