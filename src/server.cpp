#include "server.h"
#include "templating.h"

HttpServer::HttpServer() : idGeneratorJWT(uuid::generate_uuid_v4())
{
    template_render->server = this;
}

struct in_addr hostnameToIp(const char *hostname)
{
    struct hostent *hostInfo = gethostbyname(hostname);
    struct in_addr addr;

    if (hostInfo == nullptr)
    {
        throw runtime_error("Error: Unable to resolve hostname.");
        // You might want to handle the error more gracefully
        exit(1);
    }

    addr.s_addr = *(reinterpret_cast<unsigned long *>(hostInfo->h_addr));
    return addr;
}

HttpServer::HttpServer(int port_server, char *hostname, int max_connections)
    : port(port_server), MAX_CONNECTIONS(max_connections), idGeneratorJWT(uuid::generate_uuid_v4())
{

    host = hostname;
    // Convierte la dirección IP en formato de cadena a representación binaria
    ip_host_struct = hostnameToIp(host);

    template_render = new Templating();
    template_render->server = this;
}
HttpServer::HttpServer(int port_server, const string SSLcontext_server[], const char *secret_key, char *hostname, int max_connections )
    : port(port_server), MAX_CONNECTIONS(max_connections), idGeneratorJWT(string(secret_key))
{
    

    host = hostname;
    // Convierte la dirección IP en formato de cadena a representación binaria
    ip_host_struct = hostnameToIp(host);
    context.certificate = SSLcontext_server[0];
    context.private_key = SSLcontext_server[1];
    HTTPS = true;

    template_render = new Templating();
    template_render->server = this;
}

string HttpServer::Render(const string &route, map<string, string> data)
{
    return template_render->Render(route, data);
};

void HttpServer::__startListenerSSL()
{
    vector<thread> threads;

    while (true)
    {
        // Aceptar una conexión entrante
        sockaddr_in clientAddress;
        socklen_t clientAddressSize = sizeof(clientAddress);

        int clientSocket = accept(serverSocket, reinterpret_cast<sockaddr *>(&clientAddress), &clientAddressSize);
        if (clientSocket == -1)
        {
            cerr << "Error al aceptar la conexión entrante" << endl;
            continue;
        }

        // Crear el objeto SSL
        SSL *ssl = SSL_new(ssl_ctx);
        // Asociar el socket con el objeto SSL
        SSL_set_fd(ssl, clientSocket);
        // Establecer la conexión SSL
        if (SSL_accept(ssl) <= 0)
        {
            cerr << "Error al establecer la conexión SSL." << endl;
            SSL_free(ssl);
            close(clientSocket);
            continue;
        }

        // Crear un hilo para manejar la comunicación con el cliente
        thread thread(&HttpServer::__handle_request, this, move(clientSocket), move(ssl));
        threads.push_back(move(thread));
        // Eliminar hilos terminados
        threads.erase(remove_if(threads.begin(), threads.end(), [](const std::thread &t)
                                { return !t.joinable(); }),
                      threads.end());
    }
}


void HttpServer::__startListener()
{
    vector<thread> threads;

    while (true)
    {
        // Aceptar una conexión entrante
        sockaddr_in clientAddress;
        socklen_t clientAddressSize = sizeof(clientAddress);

        int clientSocket = accept(serverSocket, reinterpret_cast<sockaddr *>(&clientAddress), &clientAddressSize);
        if (clientSocket == -1)
        {
            cerr << "Error al aceptar la conexión entrante" << endl;
            continue;
        }

        // Crear un hilo para manejar la comunicación con el cliente
        SSL *ssl = NULL;
        thread thread(&HttpServer::__handle_request, this, move(clientSocket), move(ssl));
        threads.push_back(move(thread));
        // Eliminar hilos terminados
        threads.erase(remove_if(threads.begin(), threads.end(), [](const std::thread &t)
                                { return !t.joinable(); }),
                      threads.end());
    }
}


void HttpServer::startListener()
{
    if (HTTPS)
        __startListenerSSL();
    else
        __startListener();
}

int HttpServer::setup()
{
    if (HTTPS)
    {
        // Inicializar OpenSSL
        SSL_library_init();
        ssl_ctx = SSL_CTX_new(TLS_server_method());

        // Cargar certificado y clave privada
        if (SSL_CTX_use_certificate_file(ssl_ctx, context.certificate.c_str(), SSL_FILETYPE_PEM) <= 0 || !filesystem::exists(context.certificate))
        {
            cerr << "Error al cargar el certificado." << endl;
            return 1;
        }
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, context.private_key.c_str(), SSL_FILETYPE_PEM) <= 0 || !filesystem::exists(context.private_key))
        {
            cerr << "Error al cargar la clave privada." << endl;
            return 1;
        }
    }

    // Crear el socket del servidor
    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        cerr << "Error al crear el socket" << endl;
        return 1;
    }

    // Configurar la estructura de la dirección del servidor
    serverAddress.sin_family = AF_INET;
    //////////
    // struct addrinfo hints, *res;
    // memset(&hints, 0, sizeof(hints));
    // hints.ai_family = AF_INET;
    // getaddrinfo(host, nullptr, &hints, &res);
    //  struct in_addr address = reinterpret_cast<struct sockaddr_in*>(res->ai_addr)->sin_addr;
    // serverAddress.sin_addr = address;
    serverAddress.sin_addr.s_addr = INADDR_ANY; //////////////////////////////////////ARREGLAR
    serverAddress.sin_port = htons(port);

    // Enlazar el socket a la dirección y el puerto
    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) != 0)
    {
        cerr << "Error al enlazar el socket" << endl;
        return 1;
    }

    // Escuchar las conexiones entrantes
    if (listen(serverSocket, MAX_CONNECTIONS) < 0)
    {
        cerr << "Error al escuchar las conexiones" << endl;
        return 1;
    }
    if(HTTPS)
        cout << "Servidor https://" << host << ":" << port << " en ejecución " << endl;
    else
        cout << "Servidor http://" << host << ":" << port << " en ejecución " << endl;
    return 0;
}

void HttpServer::addRoute(const string &path, function<string(Request &)> handler, vector<string> methods)
{
    this->routes.push_back({path, methods, [handler](Request &args)
                      {
                          return handler(args); // Call the original handler with the query and method
                      }});
}
void HttpServer::addRouteFile(const string &endpoint, const string &extension)
{
    for(auto &route : routesFile)
        if(route.path == endpoint)
            return;
    try
    {
        this->routesFile.push_back({endpoint, content_type.find(extension)->second});
    }
    catch(const std::exception& e)
    {
        this->routesFile.push_back({endpoint, "application/force-download"});
    }   
}
void HttpServer::urlfor(const string &endpoint)
{
    size_t index = endpoint.find_last_of(".");
    string extension = "txt";
    if (string::npos != index)
        extension = endpoint.substr(index + 1);
    addRouteFile(endpoint, extension);
}
