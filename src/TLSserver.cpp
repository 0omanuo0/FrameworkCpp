#include "TLSserver.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <cstring>
#include <iostream>

std::shared_ptr<TlsConnection> TlsConnection::createClient(std::shared_ptr<uvw::TCPHandle> socket, SSL_CTX *ctx)
{
    auto conn = std::shared_ptr<TlsConnection>(new TlsConnection(std::move(socket), ctx));
    conn->postCreate();
    return conn;
}

TlsConnection::TlsConnection(std::shared_ptr<uvw::TCPHandle> socket, SSL_CTX *ctx)
    : socket_{std::move(socket)}, sslCtx_{ctx}
{
    // Create the SSL object and configure it for server mode
    ssl_ = SSL_new(sslCtx_);
    SSL_set_accept_state(ssl_); // server mode
    // Disable renegotiation, as it's a security risk
    SSL_set_options(ssl_, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION | SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET | SSL_OP_IGNORE_UNEXPECTED_EOF);
    SSL_set_max_send_fragment(ssl_, 16384);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    // Create two in‑memory BIOs, this is used because we're not using sockets directly
    readBio_ = BIO_new(BIO_s_mem());
    writeBio_ = BIO_new(BIO_s_mem());

    // Set them non-blocking
    BIO_set_nbio(readBio_, 1);
    BIO_set_nbio(writeBio_, 1);

    // Attach these BIOs to SSL
    SSL_set_bio(ssl_, readBio_, writeBio_);

    // Default onRead: echo data back
    onRead_ = [this](const char *data, std::size_t len)
    {
        asyncWrite(data, len);
    };
}

void TlsConnection::postCreate()
{
    // TCP socket events
    socket_->on<uvw::ErrorEvent>([self = shared_from_this()](const uvw::ErrorEvent &evt, uvw::TCPHandle &)
                                 {
// If there's a socket error, close the connection
#if TLS_DEBUG == 1
        std::cout << "[TLS Connection] Socket error: " << evt.what() << std::endl;
#endif
        self->publish<TlsServer::TlsErrorEvent>(TlsServer::TlsErrorEvent{evt.code(), std::move(evt.what())});
        self->close(static_cast<int>(evt.code())); 
    });

    socket_->on<uvw::CloseEvent>([self = shared_from_this()](const uvw::CloseEvent &, uvw::TCPHandle &)
                                 {
                                     // The socket has closed
                                 });

    // Whenever there's data from the socket, feed it into SSL
    socket_->on<uvw::DataEvent>([self = shared_from_this()](const uvw::DataEvent &evt, uvw::TCPHandle &)
                                { self->onSocketData(evt.data.get(), evt.length); });
}

TlsConnection::~TlsConnection()
{
    if (ssl_)
    {
        SSL_free(ssl_);
        ssl_ = nullptr; // The BIOs are freed by SSL_free() too
    }
}

void TlsConnection::setOnRead(OnReadCallback cb)
{
    onRead_ = std::move(cb);
}

void TlsConnection::setOnClose(OnCloseCallback cb)
{
    onClose_ = std::move(cb);
}

void TlsConnection::asyncWrite(const char *data, std::size_t len)
{
    if (!socket_ || socket_->closing() || len == 0)
    {
        return;
    }

    std::size_t offset = 0;
    while (offset < len)
    {
        ERR_clear_error();
        int rc = SSL_write(ssl_, data + offset, static_cast<int>(len - offset));
        if (rc > 0)
        {
            // Wrote `rc` bytes successfully
            offset += rc;
            // Send any accumulated SSL output bytes to the TCP socket
            flushSslBuffer();
        }
        else
        {
            int error = SSL_get_error(ssl_, rc);
            if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ)
            {
                // We cannot finish writing right now; queue the remaining data
                PendingWrite pending;
                pending.length = len - offset;
                pending.data = std::make_unique<char[]>(pending.length);
                std::memcpy(pending.data.get(), data + offset, pending.length);

                pendingWrites_.push_back(std::move(pending));
                scheduleFlush_ = true; // so we'll retry later
                return;
            }
            else
            {
                // A real error
                unsigned long errCode = ERR_get_error();
                char errBuff[256];
                ERR_error_string_n(errCode, errBuff, sizeof(errBuff));
#if TLS_DEBUG == 1
                std::cout << "[TLS Connection] SSL_write error: "
                          << error << " (" << errBuff << ")" << std::endl;
#endif
                this->publish(TlsServer::TlsErrorEvent{error, std::move(errBuff)});
                close(error);
                return;
            }
        }
    }

    // If we exit the loop normally, we've written the entire buffer.
    // Final flush in case any SSL data remains in the write BIO.
    flushSslBuffer();
}

void TlsConnection::close(int error)
{
    if (!ssl_ || socket_->closing())
    {
        return;
    }

    int retval;
    do
    {
        retval = SSL_shutdown(ssl_);
        if (retval < 0)
        {
            int err = SSL_get_error(ssl_, retval);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                // We need to read or write more handshake data
                flush();
                // Possibly let the event loop read more from the client
                // or continue in a state machine approach
            }
            else
            {
                // Some fatal error
                break;
            }
        }
    } while (retval == 0); // 0 => call again to complete bidirectional shutdown

    // Now it's either done (retval == 1), or there's an error.
    socket_->close();

    if (onClose_)
    {
        onClose_(error);
    }
}

void TlsConnection::onSocketData(const char *data, std::size_t len)
{
    if (!ssl_)
        return;
#if TLS_DEBUG == 1
    std::cout << "[TLS Connection] Received " << len << " bytes\n";
#endif

    // Feed data to SSL
    BIO_write(readBio_, data, len);

    constexpr std::size_t BUF_SIZE = 16 * 1024;
    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(BUF_SIZE);

    bool needsMoreData = false;

    while (true)
    {
        ERR_clear_error();
        int rc = SSL_read(ssl_, buffer.get(), BUF_SIZE);

        if (rc > 0)
        {
            // Successfully read decrypted data
            onRead_(buffer.get(), rc);
        }
        else
        {
            int error = SSL_get_error(ssl_, rc);
            if (error == SSL_ERROR_WANT_READ)
            {
                needsMoreData = true; // Indicate we need more data
                break;
            }
            else if (error == SSL_ERROR_WANT_WRITE)
            {
                flush();
                continue;
            }
            else
            {
                // Real error
                unsigned long errCode = ERR_get_error();
                char errBuff[256];
                ERR_error_string_n(errCode, errBuff, sizeof(errBuff));
#if TLS_DEBUG == 1
                std::cout << "[TLS Connection] SSL_read error: " << error << " " << errBuff << std::endl;
#endif
                this->publish(TlsServer::TlsErrorEvent{error, std::move(errBuff)});
                close(error);
                return;
            }
        }
    }

    flush();

    // If we need more data, ensure the socket keeps reading
    // if (needsMoreData && socket_ && !socket_->closing())
    // {
    //     // socket_->read(); // Ensure the next data packet is read
    // }
}

void TlsConnection::flushSslBuffer()
{
    if (!socket_ || socket_->closing())
    {
        return;
    }

    constexpr std::size_t BUF_SIZE = 1024 * 1024;
    // std::unique_ptr<char[]> buffer = std::make_unique<char[]>(BUF_SIZE);

    while (true)
    {
        int pending = BIO_pending(writeBio_);
        if (pending <= 0)
            break;

        int toRead = std::min(pending, static_cast<int>(BUF_SIZE));
        auto buf = std::make_unique<std::vector<char>>(toRead);
        auto chunk = std::unique_ptr<char[]>(new char[toRead]);
        int rc = BIO_read(writeBio_, buf->data(), toRead);
        std::memcpy(chunk.get(), buf->data(), rc);
        if (rc > 0)
        {
#if TLS_DEBUG == 1
            std::cout << "[TLS Connection] Flushing " << rc << " bytes to socket." << std::endl;
#endif
            socket_->write(std::move(chunk), rc);
            socket_->on<uvw::WriteEvent>([self = shared_from_this()](auto &, auto &) {});
        }
        else
        {
#if TLS_DEBUG == 1
            std::cerr << "[TLS Connection] BIO_read error: " << rc << std::endl;
#endif
            this->publish(TlsServer::TlsErrorEvent{SSL_get_error(ssl_, rc), "Failed to read from write BIO"});
            break;
        }
    }
}

void TlsConnection::flush()
{
    // 1) Always flush any data stuck in the SSL write BIO
    flushSslBuffer();

    // 2) Attempt sending any pending writes
    if (!pendingWrites_.empty())
    {
        // Move them aside so we don't loop infinitely if partial writes happen again
        std::vector<PendingWrite> queued;
        queued.swap(pendingWrites_);

        for (auto &pw : queued)
        {
            asyncWrite(pw.data.get(), pw.length);
            // If the connection was closed mid-way, abort
            if (!ssl_ || !socket_ || socket_->closing())
            {
                return;
            }
        }
    }
}

bool TlsConnection::needsFlush() const
{
    // If there's something in writeBio_ or we have pendingWrites_ or flagged schedule
    return (BIO_pending(writeBio_) > 0) || !pendingWrites_.empty() || scheduleFlush_;
}

void TlsConnection::maybeFlush()
{
    if (needsFlush())
    {
        scheduleFlush_ = false;
        flush();
    }
}

#include <fstream>
#include <sstream>
#include <thread>

TlsServer::TlsServer(std::shared_ptr<uvw::Loop> loop, SSL_CTX *ctx)
    : loop_{std::move(loop)}, sslCtx_{ctx}
{}

void TlsServer::flushAllConnections()
{
    // Copy the list in case flush closes connections
    auto connsCopy = activeConnections_;
    for (auto &conn : connsCopy)
    {
        conn->maybeFlush();
    }
}

void TlsServer::removeConnection(const std::shared_ptr<TlsConnection> &conn)
{
    auto it = std::find(activeConnections_.begin(), activeConnections_.end(), conn);
    if (it != activeConnections_.end())
    {
        activeConnections_.erase(it);
    }
}

SSL_CTX *TlsServer::init(std::shared_ptr<uvw::Loop> loop, const std::string &pub, const std::string &priv)
{
    // 1) Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // 2) Create an SSL_CTX for the server
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *sslCtx = SSL_CTX_new(method);

    // 3) Load server certificate & key
    // Adjust the file paths for your certificate and key
    if (SSL_CTX_use_certificate_file(sslCtx, pub.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Failed to load server certificate");
    }
    if (SSL_CTX_use_PrivateKey_file(sslCtx, priv.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Failed to load server private key");
    }

    // Optional: verify the private key
    if (!SSL_CTX_check_private_key(sslCtx))
    {
        throw std::runtime_error("Private key does not match certificate public key");
    }

    SSL_CTX_set_min_proto_version(sslCtx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(sslCtx, TLS1_2_VERSION);
    // SSL_CTX_set_cipher_list(sslCtx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384");
    SSL_CTX_set_session_cache_mode(sslCtx, SSL_SESS_CACHE_OFF);

    // set apln to http/1.1
    SSL_CTX_set_alpn_select_cb(sslCtx, [](SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *) -> int
                               {
            // (void)arg;
            if (SSL_select_next_proto((unsigned char **)out, outlen, in, inlen, (const unsigned char *)"\x08http/1.1", 9) != OPENSSL_NPN_NEGOTIATED) 
            {
                return SSL_TLSEXT_ERR_NOACK;
            }
            return SSL_TLSEXT_ERR_OK; }, nullptr);

    // forbid renegotiation and reuse
    SSL_CTX_set_options(sslCtx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION | SSL_OP_NO_RENEGOTIATION | SSL_OP_IGNORE_UNEXPECTED_EOF);

    // enable ssl debug
    SSL_CTX_set_info_callback(sslCtx, [](const SSL *ssl, int where, int ret)
                              {
                                  const char *str = SSL_state_string_long(ssl);
#if TLS_DEBUG == 1
                                  std::cout << "[OpenSSL] " << str << std::endl;
#endif
                              });

    // log tls version being used with each client and the cipher
    SSL_CTX_set_tlsext_servername_callback(sslCtx, +[](SSL *ssl, int *ad, void *arg) -> int
                                           {
        (void)ad;
        (void)arg;
        const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (servername) {
#if TLS_DEBUG == 1
            std::cout << "Client requested servername: " << servername << std::endl;
#endif
        }
        else{
#if TLS_DEBUG == 1
            std::cout << "Client did not request servername" << std::endl;
#endif
        }
#if TLS_DEBUG == 1
        std::cout << "Client requested version: " << SSL_get_version(ssl) << std::endl;
        std::cout << "Client requested cipher: " << SSL_get_cipher_name(ssl) << std::endl;
#endif
        return SSL_TLSEXT_ERR_OK; });

    // auto server = std::make_shared<TlsServer>(loop, sslCtx);

    return sslCtx; // Return the SSL_CTX for further use
}