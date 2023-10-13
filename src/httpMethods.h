#ifndef HTTP_METHOD_H
#define HTTP_METHOD_H

#include <string>
#include <vector>
#include <sstream>
#include <map>
#include <regex>

const std::string GET = "GET";
const std::string POST = "POST";
const std::string DELETE = "DELETE";

class httpMethods
{
private:
    void __loadParams(const std::string &request);
public:
    std::string method;
    std::string route;
    std::string query;
    std::map<std::string, std::string> content;

    struct httpParams
    {
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


    };

    httpParams params;

    httpMethods(){}

    httpMethods(std::string req){loadParams(req);};
    

    int loadParams(const std::string &request);
};
#endif
