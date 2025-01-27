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


#include "server_workers.hpp"
#include "server_ssl.hpp"
#include "logging.hpp"
#include "httpMethods.hpp"
#include "session.hpp"
#include "response.hpp"
#include "request.hpp"
#include "jinjaTemplating/templating.h"

class Templating;

namespace server_types{
    const std::map<std::string, std::string> content_type = {
    {"js", "application/javascript"},
    {"css", "text/css"},
    {"html", "text/html"},
    {"txt", "text/plain"}};

    typedef std::variant<std::string, Response> HttpResponse;
    typedef std::function<HttpResponse(Request&)> FunctionHandler;
    typedef std::function<Response()> defaultFunctionHandler;

    // typedef std::function<std::string()> FunctionHandler;


    struct Route
    {
        std::string path;
        std::vector<std::string> methods;
        // types::HttpResponse cache_response;
        bool cache_route;
        FunctionHandler handler;
    };
    struct RouteFile
    {
        std::string path;
        std::string type;
    };

    class HttpServerDefaults{
    private:
        std::string __default_not_found = "<h1>NOT FOUND</h1>";
        defaultFunctionHandler __not_found_handler = [this]() -> Response {
            return Response(__default_not_found, 404);
        };
        
        std::string __default_unauthorized = "<h1>UNAUTHORIZED</h1>";
        defaultFunctionHandler __unauthorized_handler = [this]() -> Response {
            return Response(__default_unauthorized, 401);
        };

        std::string __default_internal_server_error = "<html><head><title>500 Internal Server Error</title></head><body><h1>500 Internal Server Error</h1><p>The server encountered an internal error or misconfiguration and was unable to complete your request.</p></body></html>";
        defaultFunctionHandler __internal_server_error_handler = [this]() -> Response {
            return Response(__default_internal_server_error, 500);
        };

        std::string __default_bad_request = "<html><head><title>400 Bad Request</title></head><body><h1>400 Bad Request</h1><p>Your browser sent a request that this server could not understand.</p></body></html>";
        defaultFunctionHandler __redirect_handler = [this]() -> Response {
            return Response(__default_bad_request, 400);
        };
    public:
        Response getNotFound() { return __not_found_handler(); }
        Response getUnauthorized() { return __unauthorized_handler(); }
        Response getInternalServerError() { return __internal_server_error_handler(); }
        Response getBadRequest() { return __redirect_handler(); }


        void setNotFound(const defaultFunctionHandler &not_found) { __not_found_handler = not_found; }
        void setUnauthorized(const defaultFunctionHandler &unauthorized) { __unauthorized_handler = unauthorized; }
        void setInternalServerError(const defaultFunctionHandler &internal_server_error) { __internal_server_error_handler = internal_server_error; }
        void setBadRequest(const defaultFunctionHandler &bad_request) { __redirect_handler = bad_request; }

    
    };

}


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
    inline int _route_matcher(const std::string &http_route, std::unordered_map<std::string, std::string> &url_params) ;
    int _handle_route(
            std::shared_ptr<uvw::TCPHandle> sslClient, 
            server_types::Route route, 
            Sessions::Session session, 
            std::unordered_map<std::string, std::string> url_params, 
            httpHeaders http_headers
        );
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
    std::vector<server_types::RouteFile> routesFile;



public:
    // server modules pub
    server_types::HttpServerDefaults defaults;
    logging logger_;

    HttpServer(const std::string &ip, int port, const std::string ssl_context[]);
    HttpServer() : HttpServer("127.0.0.1", 5000, std::array<std::string, 2>{std::string(""), std::string("")}.data()) {}

    void addRoute(const std::string &path, const std::vector<std::string> &methods, const server_types::FunctionHandler &handler)
        { this->routes.push_back({path, methods, false, [handler](Request& req) -> server_types::HttpResponse { return handler(req); }}); }

    void addRouteFile(std::string endpoint, const std::string &extension)
    {
        // if the route dont start with / add it
        if(endpoint[0] != '/') endpoint = "/" + endpoint;

        // if exists
        for(auto &route : routesFile)
            if(route.path == endpoint)
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

    void urlfor(const std::string &path){
        size_t index = path.find_last_of(".");
        std::string extension = "txt";
        if (std::string::npos != index)
            extension = path.substr(index + 1);
        addRouteFile(path, extension);
    }
};

#endif