#ifndef SERVER_SSL_HPP
#define SERVER_SSL_HPP

#include "uvw/src/uvw.hpp"
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
        if (!ssl)
            return;

        int writeResult = SSL_write(ssl, data.get(), static_cast<int>(length));

        if (writeResult > 0)
        {
            flushPendingWrite();
        }
        else
        {
            int error = SSL_get_error(ssl, writeResult);

            if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ)
            {
                if (error == SSL_ERROR_WANT_WRITE)
                {
                    flushPendingWrite();
                }
            }
            else
            {
                std::cerr << "SSL write error" << std::endl;
                close();
            }
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

        handle->on<uvw::CloseEvent>([this](const uvw::CloseEvent &, uvw::TCPHandle &)
                                    { close(); });
        
        handle->on<uvw::WriteEvent>([this](const uvw::WriteEvent &, uvw::TCPHandle &)
                                    { flushPendingWrite(); });

        handle->on<uvw::TimerEvent>([this](const uvw::TimerEvent &, uvw::TCPHandle &) {
            std::cerr << "Timeout: Cliente no completó handshake o envío de datos" << std::endl;
            close();
        });
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
            return;
        }

        processDecryptedData();
    
        flushPendingWrite();
    }

    void performHandshake()
    {
        int result = SSL_do_handshake(ssl);
        if (result == 1)
        {
            handshakeComplete = true;
            flushPendingWrite();
            // std::cout << "SSL handshake complete!" << std::endl;
        }
        else
        {

            int error = SSL_get_error(ssl, result);
            if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
            {
                flushPendingWrite();
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
        if (!ssl || !writeBIO)
            return;

        while (BIO_ctrl_pending(writeBIO) > 0)
        {
            char buffer[4096]; // Tamaño del buffer (4KB)
            int bytesToWrite = BIO_read(writeBIO, buffer, sizeof(buffer));

            if (bytesToWrite > 0)
            {
                auto writeBuffer = std::make_unique<char[]>(bytesToWrite);
                memcpy(writeBuffer.get(), buffer, bytesToWrite);

                // Escribir los datos al cliente
                handle->write(std::move(writeBuffer), bytesToWrite);
            }
            else if (bytesToWrite == 0)
            {
                // No hay más datos pendientes
                break;
            }
            else
            {
                // Error al leer del BIO
                std::cerr << "Error reading from writeBIO" << std::endl;
                close();
                return;
            }
        }
    }

    void close()
    {
        if (ssl)
        {
            int shutdownStatus = SSL_shutdown(ssl);
            if (shutdownStatus == 0)
            {
                // SSL_shutdown necesita llamarse dos veces en una conexión bidireccional.
                SSL_shutdown(ssl);
            }
            SSL_free(ssl);
            ssl = nullptr;
        }

        if (handle && handle->active())
        {
            handle->close();
        }

        if (closeCallback)
        {
            closeCallback();
        }
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

    // SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION); // Minimum version: TLS 1.2
    // SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION); // Maximum version: TLS 1.3

    if (SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ctx))
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("SSL certificate or key error");
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    SSL_CTX_set_alpn_select_cb(ctx, [](SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) -> int
                               {
        static const unsigned char alpn_http_1_1[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
        *out = alpn_http_1_1 + 1;
        *outlen = alpn_http_1_1[0];
        return SSL_TLSEXT_ERR_OK; }, nullptr);
    // SSL_CTX_set_alpn_protos(ctx, (const unsigned char*)"\x08http/1.1", 9);

    // SSL_CTX_set_info_callback(ctx, [](const SSL *ssl, int where, int ret)
    //                           {
    //     const char *str = (where & SSL_CB_LOOP) ? "LOOP" :
    //                     (where & SSL_CB_EXIT) ? "EXIT" :
    //                     (where & SSL_CB_READ) ? "READ" : "WRITE";
    //     std::cerr << "SSL debug: " << str << " " << SSL_state_string_long(ssl) << std::endl; });
}

#endif