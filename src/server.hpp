#ifndef SERVER_H
#define SERVER_H

#include "uvw/src/uvw.hpp"
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <iostream>
#include <functional>
#include <memory>
#include <cstring>
#include <map>
#include <unordered_map>
#include <variant>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <zlib.h>
#include <list>

#include "tools/complementary_server_functions.hpp"
#include "server_workers.hpp"
#include "logging.hpp"
#include "httpMethods.hpp"
#include "session.hpp"
#include "response.hpp"
#include "request.hpp"
#include "jinjaTemplating/templating.h"

class Templating;

namespace server_types
{
    const std::map<std::string, std::string> content_type = {
        {"js", "application/javascript"},
        {"css", "text/css"},
        {"html", "text/html"},
        {"txt", "text/plain"}};

    typedef std::variant<std::string, Response> HttpResponse;
    typedef std::function<HttpResponse(Request &)> FunctionHandler;
    typedef std::function<Response()> defaultFunctionHandler;

    // typedef std::function<std::string()> FunctionHandler;

    struct Route
    {
        std::string path;
        std::vector<std::string> methods;
        bool contains_params;
        server_tools::routeRE route_regex;
        // types::HttpResponse cache_response;
        bool static_route;
        FunctionHandler handler;
        int index;
    };
    struct RouteFile
    {
        std::string path;
        std::string type;
    };

    class HttpServerDefaults
    {
    private:
        std::string __default_not_found = "<h1>NOT FOUND</h1>";
        defaultFunctionHandler __not_found_handler = [this]() -> Response
        {
            return Response(__default_not_found, 404);
        };

        std::string __method_not_allowed = "<h1>METHOD NOT ALLOWED</h1>";
        defaultFunctionHandler __method_not_allowed_handler = [this]() -> Response
        {
            return Response(__method_not_allowed, 405);
        };

        std::string __default_unauthorized = "<h1>UNAUTHORIZED</h1>";
        defaultFunctionHandler __unauthorized_handler = [this]() -> Response
        {
            return Response(__default_unauthorized, 401);
        };

        std::string __default_internal_server_error = "<html><head><title>500 Internal Server Error</title></head><body><h1>500 Internal Server Error</h1><p>The server encountered an internal error or misconfiguration and was unable to complete your request.</p></body></html>";
        defaultFunctionHandler __internal_server_error_handler = [this]() -> Response
        {
            return Response(__default_internal_server_error, 500);
        };

        std::string __default_bad_request = "<html><head><title>400 Bad Request</title></head><body><h1>400 Bad Request</h1><p>Your browser sent a request that this server could not understand.</p></body></html>";
        defaultFunctionHandler __redirect_handler = [this]() -> Response
        {
            return Response(__default_bad_request, 400);
        };

    public:
        Response getNotFound() { return __not_found_handler(); }
        Response getMethodNotAllowed() { return __method_not_allowed_handler(); }
        Response getUnauthorized() { return __unauthorized_handler(); }
        Response getInternalServerError() { return __internal_server_error_handler(); }
        Response getBadRequest() { return __redirect_handler(); }

        void setNotFound(const defaultFunctionHandler &not_found) { __not_found_handler = not_found; }
        void setMethodNotAllowed(const defaultFunctionHandler &method_not_allowed) { __method_not_allowed_handler = method_not_allowed; }
        void setUnauthorized(const defaultFunctionHandler &unauthorized) { __unauthorized_handler = unauthorized; }
        void setInternalServerError(const defaultFunctionHandler &internal_server_error) { __internal_server_error_handler = internal_server_error; }
        void setBadRequest(const defaultFunctionHandler &bad_request) { __redirect_handler = bad_request; }
    };

    struct HttpClient
    {
        std::shared_ptr<uvw::TCPHandle> client;

        bool keep_alive = false;
        unsigned long int n_requests = 0;

        std::shared_ptr<uvw::TimerHandle> timeout;
    };

    typedef struct
    {
        bool is_empty;
        Response res;
    } StaticRoute;

}

class LRUCache
{
    typedef struct
    {
        size_t size;               // size in bytes of the file
        std::string path;          // path to the file
        std::vector<char> content; // content of the file
    } File;

private:
    std::list<File> cacheList;
    std::unordered_map<std::string, File> cacheMap;
    size_t maxSizeCache;                       // in bytes of the cache
    size_t currentSize;                        // in bytes of the cache
    const static size_t maxSize = 1024 * 1024; // 1MB
public:
    LRUCache(size_t maxSize) : maxSizeCache(maxSize), currentSize(0) {}
    void put(const std::string &key, const std::vector<char> &content)
    {
        size_t size_f = content.size();

        if (!admitedSize(size_f))
            return;

        if (cacheMap.find(key) != cacheMap.end())
        {
            // move to the front
            auto it = std::find_if(cacheList.begin(), cacheList.end(), [&](const File &file)
                                   { return file.path == key; });
            if (it != cacheList.end())
            {
                cacheList.splice(cacheList.begin(), cacheList, it);
            }
            else
                throw std::runtime_error("File not found in cache list");
        }

        // if the cache is full, remove the least recently used item
        while (currentSize + size_f > maxSize)
        {
            File file = cacheList.back();
            cacheList.pop_back();
            cacheMap.erase(file.path);
            currentSize -= file.size;
        }

        // add the new item to the front of the list
        File file = {size_f, key, content};
        cacheList.push_front(file);
        cacheMap[key] = file;
        currentSize += size_f;
    }
    std::shared_ptr<const std::vector<char>> get(const std::string &key)
    {
        auto it = cacheMap.find(key);
        if (it == cacheMap.end())
            return nullptr;

        auto listIt = std::find_if(cacheList.begin(), cacheList.end(), [&](const File &file)
                                   { return file.path == key; });
        if (listIt != cacheList.end())
        {
            cacheList.splice(cacheList.begin(), cacheList, listIt);
        }

        return std::make_shared<const std::vector<char>>(it->second.content);
    }
    bool isInCache(const std::string &key)
    {
        return cacheMap.find(key) != cacheMap.end();
    }
    static bool admitedSize(size_t size)
    {
        return size > 0 && size < maxSize;
    }
};

class HttpServer
{
private:
    // server event loop variables
    std::shared_ptr<uvw::TCPHandle> server_;
    std::shared_ptr<uvw::Loop> loop_ = uvw::Loop::getDefault();
    WorkerPool::TaskQueue taskQueue_;
    WorkerPool::WorkerPool workerPool_;

    // server main functions
    void _setup_server();
    void _run_server();
    int _handle_request(std::string request, std::shared_ptr<uvw::TCPHandle> sslClient);
    inline int _route_matcher(const std::string &http_route, std::unordered_map<std::string, server_tools::ParamValue> &url_params);
    int _handle_route(
        std::shared_ptr<uvw::TCPHandle> sslClient,
        server_types::Route route,
        Sessions::Session session,
        std::unordered_map<std::string, server_tools::ParamValue> url_params,
        httpHeaders http_headers);
    int _handle_static_file(std::shared_ptr<uvw::TCPHandle> sslClient, Sessions::Session session, httpHeaders http_headers);

    // server variables
    int port_;
    std::string ip_;

    // SSL variables (NOT WORKING)
    // SSL_CTX *ctx_ = nullptr;
    // std::string ssl_context_[2];

    // server modules
    std::shared_ptr<Templating> template_render;
    std::shared_ptr<SessionsManager> sessions_;

    // server routes, files and sessions
    std::vector<server_types::Route> routes;
    std::vector<server_types::StaticRoute> static_routes;
    std::vector<server_types::RouteFile> routesFile;

    // server cache
    LRUCache file_cache_ = LRUCache(128 * 1024 * 1024); // 128MB

    std::string public_folder = "public";

    ///// TODO: needs to be loaded from the .env
    bool enable_cache = true;
    int max_age_cache = 86400;
    std::unordered_map<void *, server_types::HttpClient> clients;

    void _send_file_worker(const std::shared_ptr<uvw::TCPHandle> &client,
                           const std::string &path,
                           const std::string &realPath,
                           const std::string &type,
                           bool isCompressible);

public:
    // server modules pub
    server_types::HttpServerDefaults defaults;
    logging logger_;

    HttpServer(const std::string &ip, int port, const std::string ssl_context[]);
    HttpServer() : HttpServer("127.0.0.1", 5000, std::array<std::string, 2>{std::string(""), std::string("")}.data()) {}

    void addRoute(const std::string &path, const std::vector<std::string> &methods, const server_types::FunctionHandler &handler, bool static_route = false)
    {
        auto r_regex = server_tools::_route_contains_params(path);
        this->routes.push_back(
            {.path = path,
             .methods = methods,
             .contains_params = r_regex.found,
             .route_regex = r_regex,
             .static_route = static_route,
             .handler = [handler](Request &req) -> server_types::HttpResponse
             { return handler(req); },
             .index = static_cast<int>(this->routes.size())});

        this->static_routes.push_back({true, Response()});
    }

    void addRouteFile(std::string endpoint, const std::string &extension)
    {
        // if the route dont start with / add it
        if (endpoint[0] != '/')
            endpoint = "/" + endpoint;

        // if exists
        for (auto &route : routesFile)
            if (route.path == endpoint)
                return;

        auto it = server_types::content_type.find(extension);
        std::string contentType = (it != server_types::content_type.end()) ? it->second : "application/force-download";

        this->routesFile.push_back({endpoint, contentType});
    }

    server_types::HttpResponse NotFound() { return defaults.getNotFound(); }
    server_types::HttpResponse Unauthorized() { return defaults.getUnauthorized(); }
    server_types::HttpResponse InternalServerError() { return defaults.getInternalServerError(); }
    server_types::HttpResponse BadRequest() { return defaults.getBadRequest(); }

    server_types::HttpResponse Redirect(const std::string &path, int code = 301) { return Response("", code, {{"Location", path}}); }

    void run();

    std::string Render(const std::string &route, nlohmann::json data = nlohmann::json());

    void urlfor(const std::string &path)
    {
        size_t index = path.find_last_of(".");
        std::string extension = "txt";
        if (std::string::npos != index)
            extension = path.substr(index + 1);
        addRouteFile(path, extension);
    }
};

#endif