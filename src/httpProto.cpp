#include "httpProto.h"

void httpProtoResponse::appendParam(std::string name, std::string value)
{
    headers.insert(make_pair(name, value));
}

void httpProtoResponse::appendCookie(std::string cookie[], const std::string path, int max_age, bool http_only)
{
    std::string cookie_s = cookie[0] + "=" + cookie[1] + "; Path=" + path + "; max-Age=" + std::to_string(max_age) + (http_only ? "; HttpOnly" : "");
    headers.insert(make_pair("Set-Cookie", cookie_s));
}

std::string httpProtoResponse::defaultOK(std::string cookie[], std::string path, int max_age, bool http_only)
{
    appendCookie(cookie, path, max_age, http_only);
    return defaultOK();
}

std::string httpProtoResponse::defaultRedirect(std::string url, std::string cookie[], std::string path, int max_age, bool http_only)
{
    appendCookie(cookie, path, max_age, http_only);
    return defaultRedirect(url);
}

std::string httpProtoResponse::defaultRedirect(std::string url)
{
    headers.insert(std::make_pair("Location", url));
    return createResponseString(REDIRECT303);
}

std::string httpProtoResponse::defaultOK()
{
    headers.insert(std::make_pair("Content-Type", "text/html"));
    return createResponseString(OK200);
}
std::string httpProtoResponse::defaultNotFound()
{
    headers.insert(std::make_pair("Content-Type", "text/html"));
    return createResponseString(NOTFOUND404);
}

std::string httpProtoResponse::createResponseString(std::string type, std::pair<std::string, std::string> content)
{
    headers.insert(content);
    return createResponseString(type);
}


// funcion principal que crea la respouesta
std::string httpProtoResponse::createResponseString(std::string type)
{
    std::string response = type + "\r\n";
    if (length > 0)
        headers.insert(std::make_pair("Content-Length", std::to_string(length)));

    if (headers["Content-Type"].empty())
        headers["Content-Type"] = "text/html";
    if (headers["Content-Length"].empty())
        headers["Content-Length"] = "0";

    headers.insert(std::make_pair("Server", server));

    for (const auto &header : headers)
        response += header.first + ": " + header.second + "\r\n";

    return response + "\r\n";
}