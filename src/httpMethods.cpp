#include "httpMethods.h"
#include <iostream>
#include "url_encoding.h"


int httpMethods::loadParams(const std::string &request)
{

    size_t start = request.find(" ") + 1;
    size_t end = request.find(" ", start);
    route = request.substr(start, end - start);

    std::size_t pos = route.find('?');


    if (pos != std::string::npos){
        route = route.substr(0, pos);
        if (pos >= route.length())
            query = route.substr(pos+1);    
    }
    if (!route.empty() && route.back() == '/')// Eliminar el último carácter
            route.pop_back();
    if(route.empty())
        route = "/";
        
    if (method.empty())
    {
        method = request.substr(0, request.find(" "));
    }
    __loadParams(request);
    return 0;
}

void httpMethods::__loadParams(const std::string &request)
{
    // Extraer la ruta de la solicitud HTTP
    size_t start = request.find(" ") + 1;
    size_t end = request.find(" ", start);

    start = request.find("\r\n") + 2;
    end = request.find("\r\n", start);

    std::string content_length;
    
    while (end != std::string::npos) {

        size_t paramStart = start;
        size_t paramEnd = request.find(" ", paramStart);
        std::string param = request.substr(paramStart, paramEnd - paramStart);
    
        size_t valueStart = paramEnd + 1;
        size_t valueEnd = end;
        std::string value = request.substr(valueStart, valueEnd - valueStart);

        if (param == "Host:")
            params.host = value;
        else if (param == "User-Agent:")
            params.user_agent = value;
        else if (param == "Accept:")
        {
            std::istringstream iss(value);
            std::string token;
            while (std::getline(iss, token, ','))
                params.accept.push_back(token);
        }
        else if (param == "Cookie:")
        {
            std::istringstream iss(value);
            std::string token;
            while (std::getline(iss, token, ';')) {
                std::string key = token.substr(0, token.find("="));
                std::string value2;
                size_t equalsPos = token.find("=");
                if (equalsPos != std::string::npos) {
                    value2 = token.substr(equalsPos + 1);
                }
                params.cookies.insert(std::make_pair(key, value2));
            }
            // for (const auto& pair : params.cookies) {
            //     std::cout << pair.first << ": " << pair.second << std::endl;
            // }
        }
        else if (param == "Accept-Language:")
        {
            std::istringstream iss(value);
            std::string token;
            while (std::getline(iss, token, ','))
                params.accept_language.push_back(token);
        }
        else if (param == "Accept-Encoding:")
        {
            std::istringstream iss(value);
            std::string token;
            while (std::getline(iss, token, ','))
                params.accept_encoding.push_back(token);
        }
        else if (param == "DNT:")
            params.DNT = value;
        else if (param == "Connection:")
            params.connection = value;
        else if (param == "Upgrade-Insecure-Requests:")
            params.upgrade_insecure_requests = value;
        else if (param == "Content-Type:")
            params.content_type = value;
        else if (param == "Origin:")
            params.origin = value;
        else if (param == "Referer:")
            params.referer = value;
        else if (param == "Content-Length:")
            content_length = value;

        start = end + 2;
        end = request.find("\r\n", start);
    }

    if(!content_length.empty()){
        std::regex pattern("^\r\n*|([^=&]+)=([^&]*)");
        std::smatch matches;

        //std::string input = request.substr(request.length() - std::stoi(content_length), std::stoi(content_length));
        std::string input = request.substr(request.find_last_of("\r\n") + 1, std::stoi(content_length));

        while (std::regex_search(input, matches, pattern)) {
            content[matches[1].str()] = matches[2].str();
            input = matches.suffix();
        }
    }
}
