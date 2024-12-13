
#include "jinjaTemplating/json.hpp"
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <regex>
#include <sstream>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


namespace Requests
{

    struct ResStatus
    {
        enum ResCode : int
        {
            // list of status codes
            CONTINUE = 100,
            SWITCHING_PROTOCOLS = 101,
            PROCESSING = 102,
            EARLY_HINTS = 103,

            OK = 200,
            CREATED = 201,
            ACCEPTED = 202,
            NON_AUTHORITATIVE_INFORMATION = 203,
            NO_CONTENT = 204,
            RESET_CONTENT = 205,
            PARTIAL_CONTENT = 206,
            MULTI_STATUS = 207,
            ALREADY_REPORTED = 208,
            IM_USED = 226,

            MULTIPLE_CHOICES = 300,
            MOVED_PERMANENTLY = 301,
            FOUND = 302,
            SEE_OTHER = 303,
            NOT_MODIFIED = 304,
            USE_PROXY = 305,
            SWITCH_PROXY = 306,
            TEMPORARY_REDIRECT = 307,
            PERMANENT_REDIRECT = 308,

            BAD_REQUEST = 400,
            UNAUTHORIZED = 401,
            PAYMENT_REQUIRED = 402,
            FORBIDDEN = 403,
            NOT_FOUND = 404,
            METHOD_NOT_ALLOWED = 405,
            NOT_ACCEPTABLE = 406,
            PROXY_AUTHENTICATION_REQUIRED = 407,
            REQUEST_TIMEOUT = 408,
            CONFLICT = 409,
            GONE = 410,
            LENGTH_REQUIRED = 411,
            PRECONDITION_FAILED = 412,
            PAYLOAD_TOO_LARGE = 413,
            URI_TOO_LONG = 414,
            UNSUPPORTED_MEDIA_TYPE = 415,
            RANGE_NOT_SATISFIABLE = 416,
            EXPECTATION_FAILED = 417,
            IM_A_TEAPOT = 418,
            MISDIRECTED_REQUEST = 421,
            UNPROCESSABLE_ENTITY = 422,
            LOCKED = 423,
            FAILED_DEPENDENCY = 424,
            TOO_EARLY = 425,
            UPGRADE_REQUIRED = 426,
            PRECONDITION_REQUIRED = 428,
            TOO_MANY_REQUESTS = 429,
            REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
            UNAVAILABLE_FOR_LEGAL_REASONS = 451,

            INTERNAL_SERVER_ERROR = 500,
            NOT_IMPLEMENTED = 501,
            BAD_GATEWAY = 502,
            SERVICE_UNAVAILABLE = 503,
            GATEWAY_TIMEOUT = 504,
            HTTP_VERSION_NOT_SUPPORTED = 505,
            VARIANT_ALSO_NEGOTIATES = 506,
            INSUFFICIENT_STORAGE = 507,
            LOOP_DETECTED = 508,
            NOT_EXTENDED = 510,
            NETWORK_AUTHENTICATION_REQUIRED = 511
        };

        std::string version;
        ResCode code;
        std::string reason;
    };

    class UriScheme
    {
    private:
        const std::regex scheme_pattern = std::regex(R"(^([a-z0-9+.-]+):(?:\/\/(?:((?:[a-z0-9-._~!$&'()*+,;=:]|%[0-9A-F]{2})*)@)?((?:[a-z0-9-._~!$&'()*+,;=]|%[0-9A-F]{2})*)(?::(\d*))?(\/(?:[a-z0-9-._~!$&'()*+,;=:@\/]|%[0-9A-F]{2})*)?|(\/?(?:[a-z0-9-._~!$&'()*+,;=:@]|%[0-9A-F]{2})+(?:[a-z0-9-._~!$&'()*+,;=:@\/]|%[0-9A-F]{2})*)?)(?:\?((?:[a-z0-9-._~!$&'()*+,;=:\/?@]|%[0-9A-F]{2})*))?(?:#((?:[a-z0-9-._~!$&'()*+,;=:\/?@]|%[0-9A-F]{2})*))?$)");

    public:
        std::string scheme;
        std::string user;
        std::string password;
        std::string host;
        std::string port;
        std::string path;
        std::string query;
        std::string fragment;

        UriScheme(std::string uri_str)
        {
            std::smatch match;
            if (std::regex_match(uri_str, match, this->scheme_pattern))
            {
                this->scheme = match[1].str();
                this->user = match[2].str();
                this->password = match[3].str();
                this->host = match[4].str();
                this->port = match[5].str();
                this->path = match[6].str();
                this->query = match[7].str();
                this->fragment = match[8].str();
            }
        }
    };

    using Headers = std::unordered_map<std::string, std::string>;

    struct Response
    {
        ResStatus status;
        Headers headers;
        std::string body;

        /// @brief Convert the response to a json object
        nlohmann::json json()
        {
            return nlohmann::json::parse(body);
        }
    };


    class Request
    {
    private:
        ResStatus parseResStatus(std::string status_str)
        {
            ResStatus status;
            std::regex status_pattern(R"(HTTP/(\d+\.\d+) (\d+) (.+))");
            std::smatch match;
            if (std::regex_match(status_str, match, status_pattern))
            {
                status.version = match[1].str();
                status.code = (ResStatus::ResCode)std::stoi(match[2].str());
                status.reason = match[3].str();
            }
            return status;
        }

        Headers parseHeaders(std::string headers_str)
        {
            Headers headers;
            std::regex header_pattern(R"(([^:]+): (.+))");
            std::smatch match;
            std::string::const_iterator searchStart(headers_str.cbegin());
            while (std::regex_search(searchStart, headers_str.cend(), match, header_pattern))
            {
                headers[match[1].str()] = match[2].str();
                searchStart = match.suffix().first;
            }
            return headers;
        }
    public:
        UriScheme *uri;
        Response res;

        Request(UriScheme uri, std::string body){
            this->uri = new UriScheme(uri);
            std::string::size_type pos = body.find("\r\n\r\n");

            if (pos != std::string::npos)
            {
                std::string headers_str = body.substr(0, pos);
                std::string body_str = body.substr(pos + 4);

                this->res.headers = parseHeaders(headers_str);
                this->res.body = body_str;
                this->res.status = parseResStatus(headers_str.substr(0, headers_str.find("\r\n")));
            }


        }
    };

    int read(int socket, char *buffer, int size){
        return recv(socket, buffer, size, 0);
    }

    int startSSL(SSL_CTX *ctx, int socket, SSL *ssl){
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, socket);
        SSL_accept(ssl);

        if(SSL_accept(ssl) <= 0){
            SSL_free(ssl);
            close(socket);
            return 1;
        }
        return 0;
    }

    std::string SocketRes(std::string req_str, std::string host, int port){
        int sock = 0;
        struct sockaddr_in serv_addr;
        char buffer[1024] = {0};
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            std::cout << "\n Socket creation error \n";
            return "";
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        // Convert IPv4 and IPv6 addresses from text to binary form
        if(inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr)<=0)
        {
            std::cout << "\nInvalid address/ Address not supported \n";
            return "";
        }

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            std::cout << "\nConnection Failed \n";
            return "";
        }

        send(sock , req_str.c_str() , req_str.length() , 0 );
        std::string res;
        
        SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
        SSL *ssl = SSL_new(ssl_ctx);

        int valread;

        if(startSSL(ssl_ctx, sock, ssl) == 0)
            valread = SSL_read(ssl, buffer, 1024);
        else
            valread = read(sock, buffer, 1024);

        res = buffer;
        return res;
    }

    Request Get(const std::string &url, const Headers &headers = {}){

        UriScheme uri = UriScheme(url);

        auto port = uri.port.empty() ? "80" : uri.port;

        auto res = SocketRes("GET " + uri.path + " HTTP/1.1\r\nHost: " + uri.host + "\r\n\r\n", uri.host, std::stoi(uri.port));

        return Request(uri, res);
    }

    Request Post(const std::string &url, const Headers &headers = {}, const std::string &body = ""){
            
            UriScheme uri = UriScheme(url);
    
            auto port = uri.port.empty() ? "80" : uri.port;
    
            auto res = SocketRes("POST " + uri.path + " HTTP/1.1\r\nHost: " + uri.host + "\r\nContent-Length: " + std::to_string(body.length()) + "\r\n\r\n" + body, uri.host, std::stoi(uri.port));
    
            return Request(uri, res);
    }

}
