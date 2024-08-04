#include "httpMethods.h"




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
    }

    if (std::regex_match(this->route, match, queryRegex))
    {
        this->route = match[1];

        if (match[3].matched)
            this->query = match[3];
        else
            this->query = "";
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
        std::string param = request.substr(paramStart, paramEnd - paramStart -1);

        size_t valueStart = paramEnd + 1;
        size_t valueEnd = end;
        std::string value = request.substr(valueStart, valueEnd - valueStart);

        // find the type of the header
        auto headerType = ACEPTED_REQUEST_HEADERS.find(param);
        if (headerType != ACEPTED_REQUEST_HEADERS.end())
        {
            switch (headerType->second)
            {
            case headerType::STRING:
                this->Headers[param] = header(value);
                break;
            case headerType::LIST:
            {
                std::istringstream iss(value);
                std::vector<std::string> tokens;
                std::string token;
                while (std::getline(iss, token, ','))
                {
                    tokens.push_back(token);
                }
                this->Headers[param] = header(tokens);
                break;
            }
            case headerType::DICT:
            {
                std::istringstream iss(value);
                std::map<std::string, std::string> tokens;
                std::string token;
                while (std::getline(iss, token, ';'))
                {
                    size_t equalsPos = token.find('=');
                    std::string key = trim(token.substr(0, equalsPos));
                    std::string value2 = (equalsPos == std::string::npos) ? "" : token.substr(equalsPos + 1);
                    tokens[key] = value2;
                }
                this->Headers[param] = header(tokens);
                break;
            }
            case headerType::PAIR:
            {
                size_t equalsPos = value.find('=');
                std::string key = trim(value.substr(0, equalsPos));
                std::string value2 = (equalsPos == std::string::npos) ? "" : value.substr(equalsPos + 1);
                auto pair = std::make_pair(key, value2);
                this->Headers[param] = header(pair);
                break;
            }
            }
        }

        start = end + 2;
        end = request.find("\r\n", start);
    }

    content_length = this->Headers["Content-Length"].get<std::string>();
    if (!content_length.empty())
    {
        std::string input = request.substr(request.find_last_of("\r\n") + 1, std::stoi(content_length));
        auto a = this->Headers["Content-Type"].get<std::string>();

        Content contentBody(input, a);
        this->body = contentBody;
    }
    this->cookies = this->Headers["Cookie"].get<std::map<std::string, std::string>>();
}

Content::Content(const std::string& stringContent, const std::string& encodingType)
{
    if(encodingType == "application/x-www-form-urlencoded" )
    {
        const std::regex pattern("([^=&]+)=([^&]*)");
        std::smatch matches;

        std::string input = stringContent;
        std::map<std::string, std::string> temp_contentData;

        while (std::regex_search(input, matches, pattern))
        {
            temp_contentData[matches[1].str()] = matches[2].str();
            input = matches.suffix();
        }
        this->contentData = temp_contentData;
        this->content_type = contentType::DICT;
    }
    else if(encodingType == "application/json")
    {
        this->contentData = nlohmann::json::parse(stringContent);
        this->content_type = contentType::JSON;
    }
    else if(encodingType == "application/octet-stream")
    {
        std::vector<char> byteContent(stringContent.begin(), stringContent.end());
        this->contentData = byteContent;
        this->content_type = contentType::BYTE_ARRAY;
    }
    else
    {
        this->contentData = stringContent;
        this->content_type = contentType::STRING;
    }
}

header httpHeaders::operator[](const std::string &key)
{
    if(key == "Method" || key == "method")
        return header(this->method);
    if(key == "Route" || key == "route")
        return header(this->route);
    if(key == "Query" || key == "query")
        return header(this->query);
    return this->Headers[key];
}