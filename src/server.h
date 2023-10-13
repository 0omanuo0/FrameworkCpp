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

#include "httpMethods.h"
#include "session.h"
#include "httpProto.h"
#include "idGenerator.h"
#include "args.h"
#include "templating.h"

#ifndef SERVER_VALUES
#define SERVER_VALUES

#define BUFFER_SIZE 1024
const string SERVER_VERSION = "Soria/0.0.2b (Unix)";
const string REDIRECT = "VOID*REDIRECT";

#endif

#ifndef FILE_TYPE
#define FILE_TYPE
const map<string, string> content_type = {
    {"js", "application/javascript"},
    {"css", "text/css"},
    {"html", "text/html"},
    {"txt", "text/plain"}};
#endif

#pragma region structs
struct SSLcontext
{
    string certificate;
    string private_key;
};
struct Route
{
    string path;
    vector<string> methods;
    function<string(Args &)> handler;
};
struct RouteFile
{
    string path;
    string type;
};
#pragma endregion

class Templating;
using namespace std;
class HttpServer
{
private:
    bool HTTPS = false;
    SSLcontext context;
    SSL_CTX *ssl_ctx;
    struct in_addr ip_host_struct;
    //void __handle_client(int clientSocket);

    struct sockaddr_in serverAddress, clientAddress;
    int addrlen = sizeof(serverAddress);

    vector<Route> routes;
    vector<RouteFile> routesFile;
    vector<Session> sessions;
    string __not_found = "<h1>NOT FOUND</h1>";

    Templating *template_render;

    int __find_match_session(string id);
    Session __get_session(int index);

    int __handle_request(int socket, SSL *ssl);

    string __response_create(const string &response, Session &session);
    int __response_file(SSL *ssl, int socket, const string &path, const string &type);
    //int __response_folder(SSL *ssl, const string &response, Session &session);

    int __send_response(SSL *ssl, int socket, const string &response);
    int __send_response(SSL *ssl, int socket, const vector<string> &response);
    void __startListenerSSL();
    void __startListener();

    void addRouteFile(const string &endpoint, const string &extension);
    Session setNewSession(Session session);

public:
    int port = 8080;
    int serverSocket;
    char *host;

    int MAX_CONNECTIONS = 10;
    string default_session_name = "SessionID";
    /// @brief Constructor of the server
    HttpServer();
    /// @brief Constructor of the server, set the port and the max connections (default 10)
    HttpServer(int port_server, char *host = "0.0.0.0", int max_connections = 10);
    /// @brief Constructor of the server, set the port, the SSL context and the max connections (default 10)
    HttpServer(int port_server, const string SSLcontext_server[], char *host = "0.0.0.0", int max_connections = 10);

    /// @brief Function to start the listener
    void startListener();

    /// @brief Function to setup the server
    /// @return If dont return 0 the server is not setup correctly
    int setup();

    /// @brief Function to set the content of the 404 page
    /// @param content The content of the 404 page
    void setNotFound(string content) { __not_found = content; };

    /// @brief Function create a new route to the server
    /// @param path Route to the endpoint in browser
    /// @param handler The function to handle the request
    /// @param methods The methods allowed to access the endpoint
    void addRoute(const string &path,
                  function<string(Args &)> handler,
                  vector<string> methods);

    /// @brief Function add a file to the server
    /// @param endpoint Route to the file, also the route to the file in the browse
    void urlfor(const string &endpoint);

    /// @brief Function to render a jinja or html file
    /// @param route Route to the file
    /// @param data Content to pass to the file
    /// @return The rendered file as string to send to the client
    string Render(const string &route, map<string, string> data = map<string, string>());
};
/// @brief Function to redirect to a url
/// @param url The endpoint to redirect to
/// @return The rendered file as string to send to the client
string Redirect(string url);
/// @brief Function to find the cookie
string findCookie(HttpServer &server);

#endif // SERVER_H