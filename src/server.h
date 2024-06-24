#ifndef SERVER_H
#define SERVER_H

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <functional>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fstream>
#include <netdb.h>
#include <filesystem>
#include <variant>

#include "httpMethods.h"
#include "session.h"
#include "tools/idGenerator.h"
#include "tools/url_encoding.h"
#include "request.h"
#include "jinjaTemplating/templating.h"
#include "response.h"

#ifndef SERVER_VALUES
#define SERVER_VALUES

#define BUFFER_SIZE 1024
#define SERVER_VERSION = "Soria/0.0.2b (Unix)";
#define REDIRECT = "VOID*REDIRECT";

#endif

#ifndef FILE_TYPE
#define FILE_TYPE
const std::map<std::string, std::string> content_type = {
    {"js", "application/javascript"},
    {"css", "text/css"},
    {"html", "text/html"},
    {"txt", "text/plain"}};
#endif

namespace types{
    typedef variant<std::string, Response> HttpResponse;
    typedef function<HttpResponse(Request&)> FunctionHandler;

    struct SSLcontext
    {
        std::string certificate;
        std::string private_key;
    };
    struct Route
    {
        std::string path;
        std::vector<std::string> methods;
        FunctionHandler handler;
    };
    struct RouteFile
    {
        std::string path;
        std::string type;
    };
}

class Templating;


class HttpServer
{
private:
    int port = 8080;
    int serverSocket;
    char *host;

    bool HTTPS = false;
    types::SSLcontext context;
    SSL_CTX *ssl_ctx;
    struct in_addr ip_host_struct;
    //void __handle_client(int clientSocket);

    struct sockaddr_in serverAddress, clientAddress;
    int addrlen = sizeof(serverAddress);

    std::vector<types::Route> routes;
    std::vector<types::RouteFile> routesFile;
    std::vector<Session> sessions;
    
    std::string __not_found = "<h1>NOT FOUND</h1>";
    std::string __unauthorized = "<html><head><title>400 Bad Request</title></head><body><h1>400 Bad Request</h1><p>Your browser sent a request that this server could not understand.</p></body></html>";
    std::string __internal_server_error = "<html><head><title>500 Internal Server Error</title></head><body><h1>500 Internal Server Error</h1><p>The server encountered an internal error or misconfiguration and was unable to complete your request.</p></body></html>";

    Templating *template_render;
    int MAX_CONNECTIONS = 10;
    std::string default_session_name = "SessionID";

    idGenerator idGeneratorJWT = idGenerator("");

    std::unordered_map<std::string, std::variant<std::string, int>> data_;

    int __find_match_session(std::string id);
    Session __get_session(int index);

    int __handle_request(int socket, SSL *ssl);

    std::string __response_create(const std::string &response, Session &session);
    int __response_file(SSL *ssl, int socket, const std::string &path, const std::string &type);
    //int __response_folder(SSL *ssl, const std::string &response, Session &session);

    int __send_response(SSL *ssl, int socket, const std::string &response);
    int __send_response(SSL *ssl, int socket, const std::vector<std::string> &response);
    void __startListenerSSL();
    void __startListener();
    int __setup();

    void addRouteFile(const std::string &endpoint, const std::string &extension);
    Session setNewSession(Session session);

public:
    /// @brief Function to set the configuration of the server
    std::variant<std::string, int>& operator[](const std::string& key);

    /// @brief Function to get the port of the server
    int getPort(){return this->port;}
    /// @brief Function to get the host of the server
    std::string getHost(){return this->host;}

    /// @brief Constructor of the server
    HttpServer();
    /// @brief Constructor of the server, set the port and the max connections (default 10)
    HttpServer(int port_server, char *host = "0.0.0.0");
    /// @brief Constructor of the server, set the port, the SSL context, the secret key, the host and the max connections (default 10)
    HttpServer(int port_server, const std::string SSLcontext_server[], char *host = "0.0.0.0");

    /// @brief Function to start the listener
    void startListener();

    /// @brief Function create a new route to the server
    /// @param path Route to the endpoint in browser
    /// @param handler The function to handle the request, can return a std::string or a Response
    /// @param methods The methods allowed to access the endpoint
    void addRoute(const std::string &path, types::FunctionHandler handler, std::vector<std::string> methods);

    /// @brief Function add a file to the server
    /// @param endpoint Route to the file, also the route to the file in the browse
    void urlfor(const std::string &endpoint);

    // /// @brief Function to render a jinja or html file
    // /// @param route Route to the file
    // /// @param data Content to pass to the file
    // /// @return The rendered file as std::string to send to the client
    // std::string Render(const std::string &route, std::map<std::string, std::string> data);

    /// @brief Function to render a jinja or html file
    /// @param route Route to the file
    /// @param data Content to pass to the file
    /// @return The rendered file as std::string to send to the client
    std::string Render(const std::string &route, nlohmann::json data = nlohmann::json());
    /// @brief Function to render a jinja or html file
    /// @param route Route to the file
    /// @param data Content to pass to the file
    /// @return The rendered file as std::string to send to the client
    std::string Render(const std::string &route, const std::string& data );

    Response Redirect(std::string url);
    Response NotFound();
    Response Unauthorized();
    Response InternalServerError();
};
/// @brief Function to find the cookie
std::string findCookie(HttpServer &server);

#endif // SERVER_H