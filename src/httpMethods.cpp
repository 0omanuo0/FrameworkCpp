#include "httpMethods.h"
#include <iostream>
#include "url_encoding.h"
#include <algorithm>
#include <cctype>
#include <regex>

constexpr unsigned int hash(const char *str, int h = 0)
{
    return !str[h] ? 5381 : (hash(str, h + 1) * 33) ^ str[h];
}

std::string trim(const std::string &str)
{
    auto start = std::find_if_not(str.begin(), str.end(), [](unsigned char ch)
                                  { return std::isspace(ch); });
    auto end = std::find_if_not(str.rbegin(), str.rend(), [](unsigned char ch)
                                { return std::isspace(ch); })
                   .base();
    if (start >= end)
    {
        return "";
    }
    return std::string(start, end);
}

int httpHeaders::loadParams(const std::string &request)
{
    std::smatch match;
    const std::regex requestLineRegex(R"(^(\w+)\s+(\S+)\s+HTTP/\d\.\d(\r\n)*)");
    const std::regex queryRegex(R"(^([^\?]+)(\?(.+))?$)");

    if (std::regex_search(request, match, requestLineRegex))
    {
        this->method = match[1];
        this->route = match[2];
        std::cout << "Method: " << this->method << std::endl;
        std::cout << "Route: " << this->route << std::endl;
    }

    if (std::regex_match(this->route, match, queryRegex)) {
        this->route = match[1];

        if (match[3].matched) this->query = match[3];
        else this->query = "";
    }

    if (!this->route.empty() && this->route.back() == '/') // Eliminar el último carácter
        this->route.pop_back();
    if (this->route.empty())
        this->route = "/";

    __loadParams(request);
    return 0;
}

void httpHeaders::__loadParams(const std::string &request)
{
    // Extraer la ruta de la solicitud HTTP
    size_t start = request.find(" ") + 1;
    size_t end = request.find(" ", start);

    start = request.find("\r\n") + 2;
    end = request.find("\r\n", start);

    std::string content_length;

    while (end != std::string::npos)
    {

        size_t paramStart = start;
        size_t paramEnd = request.find(" ", paramStart);
        std::string param = request.substr(paramStart, paramEnd - paramStart);

        size_t valueStart = paramEnd + 1;
        size_t valueEnd = end;
        std::string value = request.substr(valueStart, valueEnd - valueStart);

        switch (hash(param.c_str()))
        {
        case hash("Host:"):
            this->host = value;
            break;
        case hash("User-Agent:"):
            this->user_agent = value;
            break;
        case hash("Accept:"):
        {
            std::istringstream iss(value);
            std::string token;
            while (std::getline(iss, token, ','))
            {
                this->accept.push_back(token);
            }
            break;
        }
        case hash("Cookie:"):
        {
            std::istringstream iss(value);
            std::string token;
            while (std::getline(iss, token, ';'))
            {
                std::string key = token.substr(0, token.find("="));
                std::string value2;
                size_t equalsPos = token.find("=");
                if (equalsPos != std::string::npos)
                {
                    value2 = token.substr(equalsPos + 1);
                }
                this->cookies.insert(std::make_pair(trim(key), value2));
            }
            break;
        }
        case hash("Accept-Language:"):
        {
            std::istringstream iss(value);
            std::string token;
            while (std::getline(iss, token, ','))
            {
                this->accept_language.push_back(token);
            }
            break;
        }
        case hash("Accept-Encoding:"):
        {
            std::istringstream iss(value);
            std::string token;
            while (std::getline(iss, token, ','))
            {
                this->accept_encoding.push_back(token);
            }
            break;
        }
        case hash("DNT:"):
            this->DNT = value;
            break;
        case hash("Connection:"):
            this->connection = value;
            break;
        case hash("Upgrade-Insecure-Requests:"):
            this->upgrade_insecure_requests = value;
            break;
        case hash("Content-Type:"):
            this->content_type = value;
            break;
        case hash("Origin:"):
            this->origin = value;
            break;
        case hash("Referer:"):
            this->referer = value;
            break;
        case hash("Content-Length:"):
            content_length = value;
            break;
        default:
            break;
        }

        start = end + 2;
        end = request.find("\r\n", start);
    }

    if (!content_length.empty())
    {
        const std::regex pattern("^\r\n*|([^=&]+)=([^&]*)");
        std::smatch matches;

        std::string input = request.substr(request.find_last_of("\r\n") + 1, std::stoi(content_length));

        while (std::regex_search(input, matches, pattern))
        {
            this->content[matches[1].str()] = matches[2].str();
            input = matches.suffix();
        }
    }
}
