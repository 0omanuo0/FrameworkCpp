#ifndef TLS_SERVER_HPP
#define TLS_SERVER_HPP

#include "uvw/src/uvw.hpp"
#include <functional>
#include <memory>
#include <vector>

#include <openssl/ssl.h>

/**
 * Forward declaration: We'll reference TlsServer but
 * we don't need its full definition here.
 */
class TlsServer;

/**
 * Represents an asynchronous TLS-wrapped connection on top of a uvw::TCPHandle.
 */
class TlsConnection
    : public std::enable_shared_from_this<TlsConnection>,
      public uvw::Emitter<TlsConnection>
{
public:
    // Define callback types for readability.
    using OnReadCallback = std::function<void(const char *, std::size_t)>;
    using OnCloseCallback = std::function<void(int)>;

    /**
     * Create a new TLS connection on top of a uvw TCP handle,
     * using a given SSL_CTX for server mode.
     */
    static std::shared_ptr<TlsConnection> createClient(std::shared_ptr<uvw::TCPHandle> socket, SSL_CTX *ctx);

    /**
     * Clean up SSL resources on destruction.
     */
    ~TlsConnection();

    /**
     * Start reading from the socket (uvw style).
     */
    void start();

    /**
     * Provide a callback to be invoked whenever
     * plaintext data is received from the client.
     */
    void setOnRead(OnReadCallback cb);

    /**
     * Provide a callback to be invoked if/when the connection closes
     * (with an error code or gracefully).
     */
    void setOnClose(OnCloseCallback cb);

    /**
     * Schedule an async write of plaintext data through SSL.
     */
    void asyncWrite(const char *data, std::size_t len);

    /**
     * Close the connection (with an optional error code).
     */
    void close(int error = 0);

    /**
     * Called by the server's event (e.g. uv_prepare) to see if we
     * need to flush any pending data (handshake writes, pending app writes, etc.).
     */
    void maybeFlush();

    /**
     * Return true if there's data to flush or pending writes.
     */
    bool needsFlush() const;

    bool isOpen() const { return ssl_ && !socket_->closing(); }

private:
    /**
     * Private constructor: use createClient() instead.
     */
    TlsConnection(std::shared_ptr<uvw::TCPHandle> socket, SSL_CTX *ctx);
    void postCreate();

    /**
     * Called whenever the underlying TCP socket has data (uvw::DataEvent).
     */
    void onSocketData(const char *data, std::size_t len);

    /**
     * Reads from the write BIO and sends any encrypted bytes to the socket.
     */
    void flushSslBuffer();

    /**
     * Attempts to flush pending data and/or pending writes.
     */
    void flush();

    /**
     * Represent a deferred write if SSL_write returns WANT_READ.
     */
    struct PendingWrite
    {
        std::unique_ptr<char[]> data;
        std::size_t length;
    };

    // uvw handle for the TCP socket
    std::shared_ptr<uvw::TCPHandle> socket_;

    // OpenSSL stuff
    SSL_CTX *sslCtx_{nullptr};
    SSL *ssl_{nullptr};
    BIO *readBio_{nullptr};
    BIO *writeBio_{nullptr};

    // Callbacks
    OnReadCallback onRead_{};
    OnCloseCallback onClose_{};

    // Holds data that couldn't be written to SSL because of WANT_READ
    std::vector<PendingWrite> pendingWrites_;

    // If set, we re‑try flush in the server's prepare handle
    bool scheduleFlush_{false};
};

#define TLS_DEBUG 0

/**
 * A TLS server that accepts new connections on a given address/port
 * and spawns TlsConnection objects.
 */
class TlsServer : public std::enable_shared_from_this<TlsServer>
{


public:
    typedef struct 
    {
        int code;            // a libuv error code, or 0
        std::string message; // human-readable detail
    } TlsErrorEvent;
    
    TlsServer(std::shared_ptr<uvw::Loop> loop, SSL_CTX *ctx);

    /**
     * Listen on the specified address and port.
     */
    void listen(const std::string &addr, unsigned int port);

    static SSL_CTX *init(std::shared_ptr<uvw::Loop> loop, const std::string &pub, const std::string &priv);

    /**
     * Flush all active connections that need it (e.g., handshake writes, pending writes).
     */
    void flushAllConnections();

    /**
     * Remove a connection from the active list (after it closes).
     */
    void removeConnection(const std::shared_ptr<TlsConnection> &conn);

    std::shared_ptr<uvw::Loop> loop_;
    SSL_CTX *sslCtx_{nullptr};
    std::shared_ptr<uvw::TCPHandle> server_;
    std::shared_ptr<uvw::PrepareHandle> prepare_;

    // Track all active TlsConnection objects
    std::vector<std::shared_ptr<TlsConnection>> activeConnections_;
};

#endif // TLS_SERVER_HPP