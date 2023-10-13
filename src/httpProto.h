#ifndef HTTP_PROTO_H
#define HTTP_PROTO_H

#include "server.h"

const std::string COOKIE = "GET";
const std::string USERAGENT = "POST";

const std::string OK200 = "HTTP/1.1 200 OK";
const std::string NOTFOUND404 = "HTTP/1.1 404 Not Found";
const std::string REDIRECT302 = "HTTP/1.1 302 Found";
const std::string REDIRECT303 = "HTTP/1.1 303 See Other";

#ifndef SERVER_VALUES
#define SERVER_VALUES

#define BUFFER_SIZE 1024
const std::string SERVER_VERSION = "Soria/0.0.2b (Unix)";
const std::string REDIRECT = "VOID*REDIRECT";

#endif

class httpProtoResponse
{
private:
public:
    std::map<std::string, std::string> headers;
    int length = 0;
    std::string server = SERVER_VERSION;

    httpProtoResponse(/* args */){};
    httpProtoResponse(std::map<std::string, std::string> headers_f, std::string server_f = SERVER_VERSION)
        : server(server_f), headers(headers_f){};

    void appendParam(std::string name, std::string value);
    void appendCookie(std::string cookie[2], const std::string path = "/", int max_age = 31536000, bool http_only = true);

    std::string createResponseString(std::string type);
    std::string createResponseString(std::string type, std::pair<std::string, std::string> content);

    std::string defaultRedirect(std::string url);
    std::string defaultRedirect_cookie(std::string url, std::string cookie[2], std::string path = "/", int max_age = 31536000, bool http_only = true);
    std::string defaultOK();
    std::string defaultNotFound();
    std::string defaultOK_cookie(std::string cookie[2], std::string path = "/", int max_age = 31536000, bool http_only = true);
};


#endif