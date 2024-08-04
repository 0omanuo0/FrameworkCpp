#ifndef HTTP_METHOD_H
#define HTTP_METHOD_H

#include <string>
#include <vector>
#include <sstream>
#include <map>
#include <regex>
#include <variant>

#include <iostream>
#include "tools/url_encoding.h"
#include "jinjaTemplating/json.hpp"
#include <algorithm>
#include <cctype>

const std::string GET = "GET";
const std::string POST = "POST";
const std::string PUT = "PUT";
const std::string PATCH = "PATCH";
const std::string DELETE = "DELETE";
const std::string OPTIONS = "OPTIONS";
const std::string HEAD = "HEAD";
const std::string CONNECT = "CONNECT";
const std::string TRACE = "TRACE";

// acepted request headers types
enum headerType
{
    STRING,
    LIST,
    DICT,
    PAIR
};

enum class contentType
{
    STRING,
    DICT,
    BYTE_ARRAY,
    JSON
};

// acepted request headers (just the standard ones)
const std::map<std::string, headerType> ACEPTED_REQUEST_HEADERS = {
    {"Accept", headerType::LIST},
    {"Accept-Charset", headerType::LIST},
    {"Accept-Datetime", headerType::STRING},
    {"Accept-Encoding", headerType::LIST},
    {"Accept-Language", headerType::LIST},
    {"Authorization", headerType::STRING},
    {"Cache-Control", headerType::STRING},
    {"Connection", headerType::STRING},
    {"Content-Encoding", headerType::STRING},
    {"Content-Length", headerType::STRING},
    {"Content-MD5", headerType::STRING},
    {"Content-Type", headerType::STRING},
    {"Cookie", headerType::DICT},
    {"Date", headerType::STRING},
    {"Expect", headerType::STRING},
    {"Forwarded", headerType::DICT},
    {"From", headerType::STRING},
    {"Host", headerType::STRING},
    {"If-Match", headerType::LIST},
    {"If-Modified-Since", headerType::STRING},
    {"If-None-Match", headerType::LIST},
    {"If-Range", headerType::STRING},
    {"If-Unmodified-Since", headerType::STRING},
    {"Max-Forwards", headerType::STRING},
    {"Origin", headerType::STRING},
    {"Pragma", headerType::STRING},
    {"Prefer", headerType::PAIR},
    {"Proxy-Authorization", headerType::STRING},
    {"Range", headerType::PAIR},
    {"Referer", headerType::LIST},
    {"TE", headerType::STRING},
    {"Trailer", headerType::STRING},
    {"Transfer-Encoding", headerType::STRING},
    {"User-Agent", headerType::STRING},
    {"Upgrade", headerType::LIST},
    {"Via", headerType::LIST},
    {"Warning", headerType::LIST}};

// list of accepted media types, just the standard ones
const std::vector<std::string> ACEPTED_MEDIA_TYPES = {
    "application/json",
    "application/xml",
    "application/x-www-form-urlencoded",
    "application/zip",
    "application/x-zip-compressed",
    "application/x-www-form-urlencoded",
    "application/x-gzip",
    "application/x-tar",
    "application/x-bzip2",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/octet-stream",
    "application/pdf",
    "application/msword",
    "text/plain",
    "text/html",
    "text/css",
    "text/javascript",
    "text/xml",
    "text/csv",
    "text/calendar",
    "text/vcard",

    "image/jpeg",
    "image/png",
    "image/gif",
    "image/bmp",
    "image/webp",
    "image/svg+xml",
    "image/tiff",
    "image/x-icon",

    "audio/midi",
    "audio/mpeg",
    "audio/webm",
    "audio/ogg",
    "audio/wav",
    "audio/3gpp",

    "video/webm",
    "video/ogg",
    "video/mpeg",
    "video/mp4",
    "video/3gpp",

    "multipart/form-data",
    "multipart/byteranges",
    "multipart/encrypted",

    "message/http",
    "message/imdn+xml",
    "message/partial"};

class header
{
    using headerValue = std::variant<
        std::string, std::vector<std::string>, std::map<std::string, std::string>, std::pair<std::string, std::string>>;

private:
    headerValue value;
    headerType header_type;

public:
    bool isString() { return std::holds_alternative<std::string>(value); }
    bool isList() { return std::holds_alternative<std::vector<std::string>>(value); }
    bool isDict() { return std::holds_alternative<std::map<std::string, std::string>>(value); }
    bool isPair() { return std::holds_alternative<std::pair<std::string, std::string>>(value); }

    std::string getString() { return std::get<std::string>(value); }
    std::vector<std::string> getList() { return std::get<std::vector<std::string>>(value); }
    std::map<std::string, std::string> getDict() { return std::get<std::map<std::string, std::string>>(value); }
    std::pair<std::string, std::string> getPair() { return std::get<std::pair<std::string, std::string>>(value); }

    header() = default;
    header(std::string value) : value(value), header_type(headerType::STRING) {}
    header(std::vector<std::string> value) : value(value), header_type(headerType::LIST) {}
    header(std::map<std::string, std::string> value) : value(value), header_type(headerType::DICT) {}
    header(std::pair<std::string, std::string> value) : value(value), header_type(headerType::PAIR) {}

    headerType getType()
    {
        return header_type;
    }

    template <typename T>
    T get()
    {
        // make sure that the type is correct
        if (std::holds_alternative<T>(value))
            return std::get<T>(value);
        return {};
    }
};

// content is supported to be a string, a map with key value pairs, a byte array (such as file or stream) or a json object (nlohmann::json)

class Content
{
    using contentValue = std::variant<std::string, std::map<std::string, std::string>, std::vector<char>, nlohmann::json>;

private:
    contentValue contentData;
    contentType content_type;

public:
    Content() : contentData(std::string()) {}
    Content(const std::string &stringContent, const std::string &encodingType = "text/plain");

    bool isString() { return std::holds_alternative<std::string>(contentData); }
    bool isDict() { return std::holds_alternative<std::map<std::string, std::string>>(contentData); }
    bool isByteArray() { return std::holds_alternative<std::vector<char>>(contentData); }
    bool isJson() { return std::holds_alternative<nlohmann::json>(contentData); }

    std::string getString()
    {
        if (isString())
            return std::get<std::string>(contentData);
        return "";
    }
    std::map<std::string, std::string> getDict()
    {
        if (isDict())
            return std::get<std::map<std::string, std::string>>(contentData);
        return {};
    }
    std::vector<char> getByteArray()
    {
        if (isByteArray())
            return std::get<std::vector<char>>(contentData);
        return {};
    }
    nlohmann::json getJson()
    {
        if (isJson())
            return std::get<nlohmann::json>(contentData);
        return {};
    }

    contentType getType()
    {
        return content_type;
    }

    // Get the content as a specific type
    template <typename T>
    T get()
    {
        if (std::holds_alternative<T>(contentData))
            return std::get<T>(contentData);
        else if (std::is_same<T, std::string>::value && isDict())
        {
            std::string result = "{";
            for (auto &pair : std::get<std::map<std::string, std::string>>(contentData))
            {
                result += "\"" + pair.first + "\": \"" + pair.second + "\", ";
            }
            result.pop_back();
            result.pop_back();
            result += "}";
            return result;
        }
        else if (std::is_same<T, std::string>::value && isByteArray())
        {
            std::string result;
            for (auto &byte : std::get<std::vector<char>>(contentData))
            {
                result += byte;
            }
            return result;
        }
        else if (std::is_same<T, std::string>::value && isJson())
            return std::get<nlohmann::json>(contentData).dump();
    }
};

struct HttpRequest
{
    std::string method;
    std::string route;
    std::string query;
    Content content;
};

class httpHeaders
{
private:
    void __loadParams(const std::string &request);

    std::string method;
    std::string route;
    std::string query;
    Content body;

    std::map<std::string, header> Headers;

public:
    httpHeaders() {}

    header operator[](const std::string &key);

    HttpRequest getRequest()
    {
        return {
            .method = method,
            .route = route,
            .query = query,
            .content = body};
    }

    std::map<std::string, std::string> cookies;

    std::string getMethod() { return method; }
    std::string getRoute() { return route; }
    std::string getQuery() { return query; }

    httpHeaders(std::string req) { loadParams(req); };

    int loadParams(const std::string &request);
};
#endif
