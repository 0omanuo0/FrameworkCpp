#ifndef HTTP_METHOD_H
#define HTTP_METHOD_H

#include <string>
#include <vector>
#include <sstream>
#include <map>
#include <regex>

const std::string GET = "GET";
const std::string POST = "POST";
const std::string PUT = "PUT";
const std::string PATCH = "PATCH";
const std::string DELETE = "DELETE";
const std::string OPTIONS = "OPTIONS";
const std::string HEAD = "HEAD";
const std::string CONNECT = "CONNECT";
const std::string TRACE = "TRACE";

struct HttpRequest
{
    std::string method;
    std::string route;
    std::string query;
    std::map<std::string, std::string> content;
};

class httpHeaders
{
private:
    void __loadParams(const std::string &request);

    std::string method;
    std::string route;
    std::string query;
    std::map<std::string, std::string> content;

public:
    std::string host;
    std::string user_agent;
    std::vector<std::string> accept;
    std::vector<std::string> accept_language;
    std::vector<std::string> accept_encoding;
    std::map<std::string, std::string> cookies;
    std::string DNT;
    std::string connection;
    std::string upgrade_insecure_requests;
    std::string content_type;
    std::string origin;
    std::string referer;

    HttpRequest getRequest() { return {method, route, query, content}; }

    std::string getMethod() { return method; }
    std::string getRoute() { return route; }
    std::string getQuery() { return query; }

    httpHeaders() {}

    httpHeaders(std::string req) { loadParams(req); };

    int loadParams(const std::string &request);
};
#endif
