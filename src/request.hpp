#pragma once

#include <unordered_map>
#include <vector>

#include "session.hpp"
#include "httpMethods.hpp"

class Request
{
public:
    std::unordered_map<std::string, std::string> parameters;
    
    std::string method;
    std::string route;
    std::string query;
    httpHeaders headers;

    Content content;
    std::map<std::string, std::string> form;

    Session& session;


    Request(Session& session_f)
        : session(session_f) {}

    Request(std::unordered_map<std::string, std::string> vars_f, httpHeaders method_f, Session& session_f, HttpRequest method)
        : parameters(vars_f), headers(method_f), session(session_f), method(method.method), route(method.route), query(method.query) {
            if (method.content.isDict())
                form = method.content.getDict();
            content = method.content;
        }
    // Request(std::unordered_map<std::string, std::string> vars_f, httpHeaders method_f, Session& session_f, HttpRequest method)
    //     : parameters(vars_f), headers(method_f), session(session_f), method(method.method), route(method.route), query(method.query) {}
};