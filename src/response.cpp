#include "response.h"

#ifndef HTTP_CODES
    #define HTTP_CODES
    namespace httpStatus
    {
        std::map<int, std::string> Code = {
            {200, "HTTP/1.1 200 OK"},
            {201, "HTTP/1.1 201 Created"},
            {202, "HTTP/1.1 202 Accepted"},
            {204, "HTTP/1.1 204 No Content"},
            {300, "HTTP/1.1 300 Multiple Choices"},
            {301, "HTTP/1.1 301 Moved Permanently"},
            {302, "HTTP/1.1 302 Found"},
            {303, "HTTP/1.1 303 See Other"},
            {304, "HTTP/1.1 304 Not Modified"},
            {307, "HTTP/1.1 307 Temporary Redirect"},
            {308, "HTTP/1.1 308 Permanent Redirect"},
            {400, "HTTP/1.1 400 Bad Request"},
            {401, "HTTP/1.1 401 Unauthorized"},
            {403, "HTTP/1.1 403 Forbidden"},
            {404, "HTTP/1.1 404 Not Found"},
            {405, "HTTP/1.1 405 Method Not Allowed"},
            {500, "HTTP/1.1 500 Internal Server Error"},
            {501, "HTTP/1.1 501 Not Implemented"},
            {503, "HTTP/1.1 503 Service Unavailable"}
        };
    }
#endif

Response::Response(const std::string &responseMessage, int responseCode, std::map<std::string, std::string> headers)
    :message(responseMessage), type(httpStatus::Code[responseCode]), headers(headers), statusCode(responseCode) {}

void Response::setIsFile(std::string contentType, int fileLength){
    this->isFile = true;
    this->headers["Content-Type"] = contentType;
    this->headers["Content-Length"] = std::to_string(fileLength);
}


std::string Response::generateResponse()
{
    std::string response = type + "\r\n";
    


    if(!isFile){
        auto length = message.length();
        if (length > 0) headers["Content-Length"] = std::to_string(length);

        if (headers["Content-Type"].empty()) headers["Content-Type"] = "text/html";

        if (headers["Content-Length"].empty()) headers["Content-Length"] = "0";
    }

    headers["Server"] = SERVER_VERSION;

    for (const auto &header : headers)
        response += header.first + ": " + header.second + "\r\n";


    std::string cookiesData = "Set-Cookie: ";
    for (const auto &cookie : cookies)
        cookiesData += cookie.first + "=" + cookie.second + "; ";

    cookiesData += "\r\n";
    response += cookiesData;

    return response + "\r\n" + message;
}