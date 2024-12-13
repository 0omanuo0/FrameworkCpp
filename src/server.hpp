#include <uvw.hpp>
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


#include "server_workers.hpp"
#include "server_ssl.hpp"
#include "logging.hpp"
#include "httpMethods.hpp"
#include "session.hpp"
#include "response.hpp"
#include "request.hpp"

namespace server_types{
    const std::map<std::string, std::string> content_type = {
    {"js", "application/javascript"},
    {"css", "text/css"},
    {"html", "text/html"},
    {"txt", "text/plain"}};

    typedef variant<std::string, Response> HttpResponse;
    typedef function<HttpResponse(Request&)> FunctionHandler;
    typedef function<Response(Request&)> defaultFunctionHandler;

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
        defaultFunctionHandler __not_found_handler = [this](Request &req) -> Response {
            return Response(__default_not_found, 404);
        };
        
        std::string __default_unauthorized = "<h1>UNAUTHORIZED</h1>";
        defaultFunctionHandler __unauthorized_handler = [this](Request &req) -> Response {
            return Response(__default_unauthorized, 401);
        };

        std::string __default_internal_server_error = "<html><head><title>500 Internal Server Error</title></head><body><h1>500 Internal Server Error</h1><p>The server encountered an internal error or misconfiguration and was unable to complete your request.</p></body></html>";
        defaultFunctionHandler __internal_server_error_handler = [this](Request &req) -> Response {
            return Response(__default_internal_server_error, 500);
        };

        std::string __default_bad_request = "<html><head><title>400 Bad Request</title></head><body><h1>400 Bad Request</h1><p>Your browser sent a request that this server could not understand.</p></body></html>";
        defaultFunctionHandler __redirect_handler = [this](Request &req) -> Response {
            return Response(__default_bad_request, 400);
        };
    public:
        Response getNotFound(Request &req) { return __not_found_handler(req); }
        Response getUnauthorized(Request &req) { return __unauthorized_handler(req); }
        Response getInternalServerError(Request &req) { return __internal_server_error_handler(req); }
        Response getBadRequest(Request &req) { return __redirect_handler(req); }


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
    int _handle_request(std::string request, std::shared_ptr<SSLClient> sslClient);

    // server variables
    int port_;
    std::string ip_;

    // SSL variables
    SSL_CTX *ctx_ = nullptr;
    std::string ssl_context_[2];

    // server adons
    logging logger_;
    idGenerator idGeneratorJWT = idGenerator("");
    
    // server routes, files and sessions
    std::vector<server_types::Route> routes;
    std::vector<server_types::RouteFile> routesFile;
    std::vector<Session> sessions;

    // defaults
    std::string default_session_name = "SessionID";

    // server aditional functions
    int _find_match_session(std::string id);
    Session _get_session(int index);
    Session _set_new_session(Session session);

public:
    // server defaults
    server_types::HttpServerDefaults defaults;

    HttpServer(std::string ip, int port, std::string ssl_context[])
    : ip_(ip),
      port_(port),
      taskQueue_(),
      workerPool_(4, taskQueue_)
      {
          ssl_context_[0] = ssl_context[0];
          ssl_context_[1] = ssl_context[1];
      }
    HttpServer() : HttpServer("127.0.0.1", 5000, std::array<std::string, 2>{std::string(""), std::string("")}.data()) {}

    void addRoute(const std::string &path, const std::vector<std::string> &methods, const server_types::FunctionHandler &handler)
        { this->routes.push_back({path, methods, false, [handler](Request& req) -> server_types::HttpResponse { return handler(req); }}); }

    void run();
};