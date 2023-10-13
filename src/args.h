#pragma once

#include <vector>
#include <openssl/ssl.h>
#include "httpMethods.h"
#include "session.h"

class Args
{
public:
    const std::vector<std::string> vars;
    const std::string query;
    httpMethods request;
    Session& session;
    SSL *ssl;
    int socket;
    Args(std::vector<std::string> vars_f, int socket_f, SSL *ssl, httpMethods method_f, Session& session_f)
        : vars(vars_f), socket(socket_f), ssl(ssl), request(method_f), session(session_f) {}
    Args(std::vector<std::string> vars_f, httpMethods method_f, Session& session_f)
        : vars(vars_f), request(method_f), session(session_f) {}
};