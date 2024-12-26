#pragma once

#include "uvw/src/uvw.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <memory>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <vector>

namespace ssl_server
{

    /**
     * @brief RAII wrapper for SSL and its associated BIOs.
     *
     * Manages creation and destruction of SSL and BIO resources.
     * We intentionally do NOT call SSL_shutdown() here to give the owner (SSLClient)
     * full control of the shutdown sequence.
     */
    class SSLWrapper
    {
    public:
        explicit SSLWrapper(SSL_CTX *sslCtx)
        {
            if (!sslCtx)
            {
                throw std::runtime_error("SSL_CTX is null. Cannot create SSL instance.");
            }

            ssl_ = SSL_new(sslCtx);
            if (!ssl_)
            {
                throw std::runtime_error("Failed to create SSL structure.");
            }

            readBIO_ = BIO_new(BIO_s_mem());
            writeBIO_ = BIO_new(BIO_s_mem());
            if (!readBIO_ || !writeBIO_)
            {
                // Cleanup on error
                if (readBIO_)
                {
                    BIO_free(readBIO_);
                }
                if (writeBIO_)
                {
                    BIO_free(writeBIO_);
                }
                SSL_free(ssl_);
                ssl_ = nullptr;
                throw std::runtime_error("Failed to create readBIO/writeBIO.");
            }

            // Associate BIOs with the SSL instance
            // In server mode, OpenSSL expects to read data from readBIO_ and write data to writeBIO_
            SSL_set_bio(ssl_, readBIO_, writeBIO_);
            SSL_set_accept_state(ssl_); // Server mode
        }

        ~SSLWrapper()
        {
            // We do NOT call SSL_shutdown() here so that SSLClient can manage the
            // two-phase shutdown handshake as needed. We just free the SSL structure.
            if (ssl_)
            {
                SSL_free(ssl_);
                ssl_ = nullptr;
            }
        }

        // No copy or move to avoid double frees or invalid states
        SSLWrapper(const SSLWrapper &) = delete;
        SSLWrapper &operator=(const SSLWrapper &) = delete;
        SSLWrapper(SSLWrapper &&) = delete;
        SSLWrapper &operator=(SSLWrapper &&) = delete;

        SSL *getSSL() const { return ssl_; }
        BIO *getReadBIO() const { return readBIO_; }
        BIO *getWriteBIO() const { return writeBIO_; }

    private:
        SSL *ssl_{nullptr};
        BIO *readBIO_{nullptr};
        BIO *writeBIO_{nullptr};
    };

    /**
     * @brief Manages an SSL connection over a uvw::TCPHandle.
     *
     * Responsibilities:
     *  - SSL handshake
     *  - Encrypted read/writes
     *  - Notification of close events and data arrival
     */
    class SSLClient
    {
    public:
        using DataCallback = std::function<void(const char *, std::size_t)>;
        using CloseCallback = std::function<void()>;

        /**
         * @brief Constructs an SSLClient with a given TCP handle and SSL context.
         * @param tcpHandle Already connected uvw::TCPHandle
         * @param sslCtx    Pre-configured SSL_CTX (TLS server mode)
         */
        SSLClient(std::shared_ptr<uvw::TCPHandle> tcpHandle, SSL_CTX *sslCtx)
            : handle_{std::move(tcpHandle)}
        {
            if (!handle_)
            {
                throw std::runtime_error("TCPHandle is null. Cannot create SSLClient.");
            }
            sslWrapper_ = std::make_unique<SSLWrapper>(sslCtx);
            setupEvents();
        }

        ~SSLClient()
        {
            close();
        }

        /**
         * @brief Registers a callback for decrypted data arrival.
         */
        void onData(const DataCallback &callback)
        {
            dataCallback_ = callback;
        }

        /**
         * @brief Registers a callback for when the connection closes.
         */
        void onClose(const CloseCallback &callback)
        {
            closeCallback_ = callback;
        }

        /**
         * @brief Writes data to the SSL connection. If the handshake is incomplete,
         *        data is queued until the handshake finishes.
         *
         * @param data   Buffer containing data to send.
         * @param length Number of bytes in the buffer.
         */
        void write(std::unique_ptr<char[]> data, std::size_t length)
        {
            if (!sslWrapper_)
            {
                std::cerr << "[SSLClient::write] Cannot write, SSLWrapper is null.\n";
                return;
            }

            // If handshake isn't complete, queue the data for later sending
            if (!handshakeComplete_)
            {
                queueData(std::move(data), length);
                return;
            }

            writeInternal(std::move(data), length);
        }

    private:
        /**
         * @brief Writes data to the SSL layer and flushes pending writes to the TCP socket.
         *
         * @param data   Buffer to write
         * @param length Size of the buffer
         */
        void writeInternal(std::unique_ptr<char[]> data, std::size_t length)
        {
            SSL *ssl = sslWrapper_->getSSL();
            if (!ssl)
            {
                std::cerr << "[SSLClient::writeInternal] SSL is null.\n";
                return;
            }

            const int writeResult = SSL_write(ssl, data.get(), static_cast<int>(length));
            if (writeResult > 0)
            {
                flushPendingWrite();
            }
            else
            {
                const int error = SSL_get_error(ssl, writeResult);
                if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ)
                {
                    // Not ready to write/read yet, will retry on next I/O
                    if (error == SSL_ERROR_WANT_WRITE)
                    {
                        flushPendingWrite();
                    }
                }
                else
                {
                    std::cerr << "[SSLClient::writeInternal] SSL_write error: " << error << "\n";
                    close();
                }
            }
        }

        /**
         * @brief Stores data in a handshake queue for sending once the handshake completes.
         */
        void queueData(std::unique_ptr<char[]> data, std::size_t length)
        {
            handshakeQueue_.emplace_back(std::move(data), length);
        }

        /**
         * @brief Called once the handshake is complete to flush any queued data.
         */
        void flushHandshakeQueue()
        {
            for (auto &item : handshakeQueue_)
            {
                writeInternal(std::move(item.first), item.second);
            }
            handshakeQueue_.clear();
        }

        /**
         * @brief Sets up uvw event listeners for reading, closing, errors, etc.
         */
        void setupEvents()
        {
            handle_->on<uvw::DataEvent>([this](const uvw::DataEvent &event, uvw::TCPHandle &)
                                        { handleData(event.data.get(), event.length); });

            handle_->on<uvw::EndEvent>([this](const uvw::EndEvent &, uvw::TCPHandle &)
                                       { close(); });

            handle_->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &event, uvw::TCPHandle &)
                                         { std::cerr << "[SSLClient::setupEvents] TCP Error: " << event.what() << "\n"; });

            handle_->on<uvw::CloseEvent>([this](const uvw::CloseEvent &, uvw::TCPHandle &)
                                         { close(); });

            // When uvw finishes writing to the TCP socket, try to flush the SSL write queue
            handle_->on<uvw::WriteEvent>([this](const uvw::WriteEvent &, uvw::TCPHandle &)
                                         { flushPendingWrite(); });

            // Typically, you'd create a uvw::TimerHandle separately. Binding a TimerEvent to a TCPHandle
            // isn't common. Make sure you're actually setting up a TimerHandle somewhere.
            handle_->on<uvw::TimerEvent>([this](const uvw::TimerEvent &, uvw::TCPHandle &)
                                         {
            std::cerr << "[SSLClient::setupEvents] Timeout: Client did not complete handshake or send data.\n";
            close(); });
        }

        /**
         * @brief Handles incoming encrypted data from the TCP connection.
         *
         * @param data   Pointer to the encrypted data.
         * @param length Number of bytes available in data.
         */
        void handleData(const char *data, std::size_t length)
        {
            if (!sslWrapper_)
            {
                std::cerr << "[SSLClient::handleData] SSLWrapper is null.\n";
                return;
            }
            if (length == 0)
            {
                return;
            }

            // Loop until we've written all data to the read BIO to handle partial writes
            std::size_t totalWritten = 0;
            while (totalWritten < length)
            {
                int ret = BIO_write(sslWrapper_->getReadBIO(),
                                    data + totalWritten,
                                    static_cast<int>(length - totalWritten));
                if (ret <= 0)
                {
                    std::cerr << "[SSLClient::handleData] Error writing to readBIO. Return: " << ret << "\n";
                    return;
                }
                totalWritten += static_cast<std::size_t>(ret);
            }

            // If handshake is not complete, attempt it
            if (!handshakeComplete_)
            {
                performHandshake();
            }
            else
            {
                // Otherwise, process the decrypted data
                processDecryptedData();
                flushPendingWrite();
            }
        }

        /**
         * @brief Performs the SSL handshake. Sets handshakeComplete_ if successful.
         */
        void performHandshake()
        {
            if (!sslWrapper_)
            {
                std::cerr << "[SSLClient::performHandshake] SSLWrapper is null.\n";
                return;
            }

            SSL *ssl = sslWrapper_->getSSL();
            if (!ssl)
            {
                std::cerr << "[SSLClient::performHandshake] SSL is null.\n";
                return;
            }

            const int result = SSL_do_handshake(ssl);
            if (result == 1)
            {
                handshakeComplete_ = true;
                // Send any queued data now that handshake is complete
                flushHandshakeQueue();
                flushPendingWrite();
            }
            else
            {
                const int error = SSL_get_error(ssl, result);
                if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
                {
                    // More I/O needed
                    flushPendingWrite();
                }
                else
                {
                    std::cerr << "[SSLClient::performHandshake] Handshake error: " << error << "\n";
                    ERR_print_errors_fp(stderr);
                    close();
                }
            }
        }

        /**
         * @brief Reads decrypted data from SSL and calls dataCallback_ if present.
         */
        void processDecryptedData()
        {
            if (!sslWrapper_)
            {
                return;
            }

            SSL *ssl = sslWrapper_->getSSL();
            if (!ssl)
            {
                return;
            }

            // Read data in a loop because there could be multiple records pending
            while (true)
            {
                char buffer[65536]; // 64KB
                int bytesRead = SSL_read(ssl, buffer, static_cast<int>(sizeof(buffer)));
                if (bytesRead > 0)
                {
                    // Notify the upper layer about the data
                    if (dataCallback_)
                    {
                        dataCallback_(buffer, static_cast<std::size_t>(bytesRead));
                    }
                }
                else if (bytesRead == 0)
                {
                    // Peer closed the connection
                    close();
                    break;
                }
                else
                {
                    // Check SSL error
                    handleSSLError(bytesRead);
                    break;
                }
            }
        }

        /**
         * @brief Sends pending data from the write BIO to the TCP socket.
         */
        void flushPendingWrite()
        {
            if (!sslWrapper_)
            {
                return;
            }

            BIO *writeBIO = sslWrapper_->getWriteBIO();
            if (!writeBIO)
            {
                return;
            }

            while (BIO_ctrl_pending(writeBIO) > 0)
            {
                char buffer[4096]; // 4KB
                int bytesToWrite = BIO_read(writeBIO, buffer, static_cast<int>(sizeof(buffer)));
                if (bytesToWrite > 0)
                {
                    auto writeBuffer = std::make_unique<char[]>(bytesToWrite);
                    std::memcpy(writeBuffer.get(), buffer, bytesToWrite);

                    // Send encrypted data to the client
                    handle_->write(std::move(writeBuffer), static_cast<unsigned int>(bytesToWrite));
                }
                else if (bytesToWrite == 0)
                {
                    // No more pending data
                    break;
                }
                else
                {
                    std::cerr << "[SSLClient::flushPendingWrite] Error reading from writeBIO.\n";
                    close();
                    return;
                }
            }
        }

        /**
         * @brief Closes the SSL session and the TCP handle.
         */
        void close()
        {
            // Avoid multiple calls to close
            if (!sslWrapper_)
            {
                return;
            }

            // Perform a two-phase SSL shutdown if possible
            if (SSL *ssl = sslWrapper_->getSSL())
            {
                int shutdownStatus = SSL_shutdown(ssl);
                if (shutdownStatus == 0)
                {
                    // Attempt a second call to complete bidirectional closure
                    SSL_shutdown(ssl);
                }
            }
            sslWrapper_.reset();

            // Close the TCP socket if it's still active
            if (handle_ && handle_->active())
            {
                handle_->close();
            }

            // Notify listeners
            if (closeCallback_)
            {
                closeCallback_();
            }
        }

        /**
         * @brief Handles SSL read errors.
         */
        void handleSSLError(int sslReadResult)
        {
            SSL *ssl = sslWrapper_ ? sslWrapper_->getSSL() : nullptr;
            if (!ssl)
            {
                return;
            }

            int error = SSL_get_error(ssl, sslReadResult);
            switch (error)
            {
            case SSL_ERROR_ZERO_RETURN:
                // Peer closed the connection
                close();
                break;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                // Non-fatal; just need more I/O
                break;
            default:
                std::cerr << "[SSLClient::handleSSLError] SSL read error: " << error << "\n";
                close();
                break;
            }
        }

    private:
        std::shared_ptr<uvw::TCPHandle> handle_;
        std::unique_ptr<SSLWrapper> sslWrapper_;

        bool handshakeComplete_{false};

        // Any data queued before handshake completes
        std::vector<std::pair<std::unique_ptr<char[]>, std::size_t>> handshakeQueue_;

        // User callbacks
        DataCallback dataCallback_{nullptr};
        CloseCallback closeCallback_{nullptr};
    };

    /**
     * @brief Initializes and configures the SSL context (SSL_CTX) with recommended production settings.
     *
     * @param[out] ctx       Reference to the SSL_CTX* to be created.
     * @param[in]  certFile  Path to the certificate file (PEM format).
     * @param[in]  keyFile   Path to the private key file (PEM format).
     */
    inline void configureOpenSSL(SSL_CTX *&ctx, const char *certFile, const char *keyFile)
    {
        // Modern OpenSSL initialization.
        // For older OpenSSL, SSL_library_init, SSL_load_error_strings, etc. might be used.
        OPENSSL_init_ssl(0, nullptr);    // Initialize SSL
        OPENSSL_init_crypto(0, nullptr); // Initialize Crypto

        ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx)
        {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("Failed to create SSL context.");
        }

        // Load server certificate and private key
        if (SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0 ||
            !SSL_CTX_check_private_key(ctx))
        {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("Failed to load SSL certificate/key or check the private key.");
        }

        // Enforce TLS 1.2–1.3
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

        // Disable older protocols (SSLv2, SSLv3)
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

        // Example: Set ECDH automatically (for perfect forward secrecy with ECDHE ciphers)
        // If not available, consider SSL_CTX_set_ecdh_auto(ctx, 1) on older versions:
        SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
        SSL_CTX_set_ecdh_auto(ctx, 1);

        // Set a cipher list that prioritizes strong elliptic-curve ciphers (example)
        // Adjust to your organization's security policy:
        if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                                         "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
                                         "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                                         "!aNULL:!eNULL:!MD5:!DSS") != 1)
        {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("Failed to set SSL cipher list.");
        }

        // ALPN selection callback for HTTP/1.1 (can be adapted for HTTP/2 or other protocols).
        SSL_CTX_set_alpn_select_cb(ctx, [](SSL * /*ssl*/, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void * /*arg*/) -> int
                                   {
            static const unsigned char alpn_http_1_1[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
            // Here you would parse 'in' if you support multiple protocols.
            // For simplicity, we'll always pick http/1.1.
            *out    = alpn_http_1_1 + 1;
            *outlen = alpn_http_1_1[0];
            return SSL_TLSEXT_ERR_OK; }, nullptr);

        // Optionally, you could explicitly set ALPN protocols:
        // const unsigned char alpnProtos[] = "\x08http/1.1";
        // SSL_CTX_set_alpn_protos(ctx, alpnProtos, sizeof(alpnProtos) - 1);

        // Optional: debug callback for SSL handshake logging
        // SSL_CTX_set_info_callback(ctx,
        //     [](const SSL *ssl, int where, int ret) {
        //         const char *str =
        //             (where & SSL_CB_LOOP) ? "LOOP" :
        //             (where & SSL_CB_EXIT) ? "EXIT" :
        //             (where & SSL_CB_READ) ? "READ" : "WRITE";
        //         std::cerr << "[DEBUG SSL] " << str << ": " << SSL_state_string_long(ssl) << "\n";
        //     }
        // );
    }

} // namespace ssl_server
