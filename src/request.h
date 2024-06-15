#pragma once

#include <vector>
#include <openssl/ssl.h>
#include "httpMethods.h"
#include "session.h"
#include <unordered_map>
#include "httpMethods.h"

class Request
{
public:
    std::unordered_map<std::string, std::string> parameters;
    
    std::string method;
    std::string route;
    std::string query;
    httpHeaders headers;

    std::map<std::string, std::string> content;

    Session& session;

    SSL *ssl;
    int socket;


    Request(std::unordered_map<std::string, std::string> vars_f, int socket_f, SSL *ssl, httpHeaders method_f, Session& session_f, HttpRequest method)
        : parameters(vars_f), socket(socket_f), ssl(ssl), headers(method_f), session(session_f), method(method.method), route(method.route), query(method.query), content(method.content) {}
    Request(std::unordered_map<std::string, std::string> vars_f, httpHeaders method_f, Session& session_f, HttpRequest method)
        : parameters(vars_f), headers(method_f), session(session_f), method(method.method), route(method.route), query(method.query), content(method.content) {}
};