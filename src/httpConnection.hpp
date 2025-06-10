#ifndef HTTP_CONNECTION_HPP
#define HTTP_CONNECTION_HPP

#include "uvw/src/uvw.hpp"
#include "TLSserver.hpp"
#include <cstring>

// this code handles both HTTP and HTTPS connections independently of the underlying transport layer (TCP or TLS).

class HttpConnection : public std::enable_shared_from_this<HttpConnection>,
                       public uvw::Emitter<HttpConnection>
{
public:
    HttpConnection(std::shared_ptr<uvw::TCPHandle> socket)
        : socket_(std::move(socket))
    {
        tlsConn_ = nullptr; // Assuming no SSL_CTX for now
    }
    HttpConnection(std::shared_ptr<uvw::TCPHandle> socket, std::shared_ptr<TlsConnection> tlsConn)
        : socket_(std::move(socket)), tlsConn_(std::move(tlsConn))
    {
        if (tlsConn_)
            isTls_ = true; // This connection is using TLS
        else
            isTls_ = false; // No TLS connection
    }
    ~HttpConnection() override = default;

    inline void asyncWrite(std::string_view data)
    {
        asyncWrite(data.data(), data.size());
    }

    /* raw-pointer entry that every caller funnels through  */
    void asyncWrite(const char *data, std::size_t len)
    {
        if (len == 0)
            return; // nothing to send

        if (tlsConn_ && isTls_)
        {                                    // TLS branch
            tlsConn_->asyncWrite(data, len); // ← TlsConnection copies internally
        }
        else if (socket_)
        { // plain-TCP branch
            auto buf = std::make_unique<char[]>(len);
            std::memcpy(buf.get(), data, len);

            /* MOVE the smart-pointer so uvw owns it until WriteEvent */
            socket_->write(std::move(buf), len); // ownership transferred
        }
    }

    int _send_response(const std::string &response)
    {
        if (!isOpen()) // connection already closed
            return -1;

        asyncWrite(response); // std::string → string_view → asyncWrite
        return 0;
    }

    bool isOpen() const
    {
        return (tlsConn_ && tlsConn_->isOpen()) || (socket_ && !socket_->closing());
    }

    bool active() const
    {
        return (this->isOpen() && socket_ && socket_->active()) || (socket_ && socket_->active());
    }

    uvw::Loop &loop()
    {
        if (socket_)
        {
            return socket_->loop();
        }
        else
        {
            throw std::runtime_error("Socket is not initialized");
        }
    }

    void *getClient()
    {
        if (socket_)
        {
            return socket_.get();
        }
        else
        {
            throw std::runtime_error("Socket is not initialized");
        }
    }

private:
    std::shared_ptr<uvw::TCPHandle> socket_;
    std::shared_ptr<TlsConnection> tlsConn_;
    bool isTls_ = false; // Indicates if this connection is using TLS
};

#endif // HTTP_CONNECTION_HPP