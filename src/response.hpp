#pragma once

#include <string>
#include <map>

#ifndef SERVER_VALUES
    #define SERVER_VALUES

    #define BUFFER_SIZE 1024
    #define SERVER_VERSION "Soria/0.0.2b (Unix)"
#endif

namespace httpStatus{
    extern std::map<int, std::string> Code;
}

class Response
{
private:
    /* data */
    std::string type = httpStatus::Code[200];
    int statusCode = 200;
    std::string message;
    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> cookies;

    bool isFile = false;
public:
    Response(){}

    // copy constructor
    Response(const Response &other)
        : type(other.type), statusCode(other.statusCode), message(other.message),
          headers(other.headers), cookies(other.cookies), isFile(other.isFile) {}

    Response(const std::string &responseMessage, int responseCode=200, std::map<std::string, std::string> headers = {});
    int getResponseCode() {return this->statusCode;}

    bool isEmpty() {return this->message.empty();}

    const std::string &getMessage() {return this->message;}
    void setMessage(const std::string &message) {this->message = message;}

    void addHeader(std::string key, std::string value) {this->headers[key] = value;}
    void addSessionCookie(std::string key, std::string sessionID) {this->cookies[key] = sessionID;}
    void setIsFile(std::string contentType, int fileLength);
    std::string generateResponse();
};


// example of usage
// Response res = Response("Hello World", 200, {{"Content-Type", "text/html"}});
// res.addSessionCookie("sessionID", uuid::generateUUIDv4());
// res.generateResponse()