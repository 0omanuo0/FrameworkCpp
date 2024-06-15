#include "server.h"
#include "url_encoding.h"
#include <unordered_map>

#ifndef RESPONSE_TYPE
#define RESPONSE_TYPE
const std::string response_type[] = {"FOLDER", "FILE", "URL"}; // orden de cada tipo de respuesta
#endif


bool __match_path_with_route(const std::string &path, const std::string &routePath, std::unordered_map<std::string, std::string> &url_params)
{
    const std::regex routeRegex("^" + std::regex_replace(routePath, std::regex("<([^>]+)>"), "([^/]+)") + "$");
    std::smatch matches;

    if (!std::regex_match(path, matches, routeRegex))
    {
        return false;
    }

    std::regex varNameRegex("<([^>]+)>");
    auto varNameBegin = std::sregex_iterator(routePath.begin(), routePath.end(), varNameRegex);
    auto varNameEnd = std::sregex_iterator();

    for (std::sregex_iterator i = varNameBegin; i != varNameEnd; ++i)
    {
        std::smatch match = *i;
        std::string varName = match.str(1);
        url_params[varName] = matches[std::distance(varNameBegin, i) + 1].str();
    }

    return true;
}

bool __route_contains_params(const std::string &routePath)
{
    const std::regex paramRegex("<[^>]+>");
    return std::regex_search(routePath, paramRegex);
}

std::string __recv(SSL *ssl, int socket)
{
    char buffer[BUFFER_SIZE];
    std::string data;
    int total = 0;

    while (true)
    {
        int nRecvd;

        if (ssl != NULL)
            nRecvd = SSL_read(ssl, buffer, sizeof(buffer));
        else if (socket != NULL)
            nRecvd = recv(socket, buffer, sizeof(buffer), 0);
        else
        {
            // Indica un error, ya que ni SSL ni socket están disponibles
            std::cerr << "Ni SSL ni socket disponibles" << std::endl;
            return std::string();
        }

        if (nRecvd <= 0)
        {
            int error;
            if (ssl != NULL)
                error = SSL_get_error(ssl, nRecvd);
            else if (socket != NULL)
                error = errno; // Usamos errno para obtener el código de error del sistema

            if (error == SSL_ERROR_WANT_READ)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            else if (error == SSL_ERROR_ZERO_RETURN || error == SSL_ERROR_SYSCALL || error == 0)
                // El otro extremo ha cerrado la conexión o se ha producido un error
                break;
            else
            {
                std::cerr << "Error al leer la petición" << std::endl;
                return std::string();
            }
        }

        data.append(buffer, nRecvd);

        if (nRecvd < sizeof(buffer))
            // No se pueden leer más datos, termina el bucle
            break;
    }
    return data;
}

string HttpServer::__response_create(const std::string &response, Session &session)
{
    // respuestas https
    std::string response_with_header;
    httpProtoResponse response_server;
    if (response.empty())
    {
        response_server.length = __not_found.length();
        return response_server.defaultNotFound() + __not_found;
    }
    else
    {
        if (response.substr(0, REDIRECT.length()) == REDIRECT) ////////////////esto no se puede quedar asi
        {
            std::string cookie[] = {this->default_session_name, this->idGeneratorJWT.generateJWT(session.toString())};
            
            if (cookie[1].empty())
                response_with_header = response_server.defaultRedirect(response.substr(REDIRECT.length()));
            else
                response_with_header = response_server.defaultRedirect(response.substr(REDIRECT.length()), cookie);
        }
        else
        {
            response_server.length = response.length();
            std::string cookie[] = {this->default_session_name, this->idGeneratorJWT.generateJWT(session.toString())};

            if (cookie[1].empty())
                response_with_header += response_server.defaultOK();
            else
                response_with_header += response_server.defaultOK(cookie);
            response_with_header += response;
        }
    }
    return response_with_header;
}

int HttpServer::__response_file(SSL *ssl, int socket, const std::string &path, const std::string &type)
{
    std::vector<std::string> data_to_send = std::vector<std::string>();
    httpProtoResponse response_serv = httpProtoResponse();

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open() && !file.good())
    {
        std::cerr << "Error al abrir el archivo: " << path << std::endl;
        __send_response(ssl, socket, response_serv.defaultNotFound());
        return -1;
    }

    // Obtener el tamaño del archivo
    file.seekg(0, std::ios::end);
    std::streampos fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Leer el contenido del archivo en un búfer
    std::vector<char> buffer_f(fileSize);
    if (!file.read(buffer_f.data(), fileSize))
    {
        std::cerr << "Error al leer el archivo: " << path << std::endl;
        __send_response(ssl, socket, response_serv.defaultNotFound());
        return -1;
    }

    // Construir la respuesta HTTP con el encabezado adecuado

    response_serv.appendParam("Content-Type", type);
    response_serv.appendParam("Content-Disposition", "attachment; filename=\"" + path.substr(path.find_last_of("/") + 1) + "\"");
    response_serv.length = fileSize;

    data_to_send.push_back(response_serv.defaultOK());
    data_to_send.push_back(std::string(buffer_f.begin(), buffer_f.end()));
    __send_response(ssl, socket, data_to_send);
    return 0;
}

int HttpServer::__send_response(SSL *ssl, int socket, const std::vector<std::string> &response)
{
    if (ssl != NULL)
    {
        // Enviar el encabezado y el contenido del archivo al cliente
        if (SSL_write(ssl, response[0].c_str(), response[0].size()) < 0)
        {
            std::cerr << "Error al enviar el encabezado HTTP" << std::endl;
            return -1;
        }

        if (SSL_write(ssl, response[1].c_str(), response[1].size()) < 0)
        {
            std::cerr << "Error al enviar el contenido del archivo" << std::endl;
            return -1;
        }
    }
    else{
        // Enviar el encabezado y el contenido del archivo al cliente
        if (send(socket, response[0].c_str(), response[0].size(), 0) < 0)
        {
            std::cerr << "Error al enviar el encabezado HTTP" << std::endl;
            return -1;
        }

        if (send(socket, response[1].c_str(), response[1].size(), 0) < 0)
        {
            std::cerr << "Error al enviar el contenido del archivo" << std::endl;
            return -1;
        }
    }

    return 0;
}

int HttpServer::__send_response(SSL *ssl, int socket, const std::string &response)
{
    if (ssl != NULL)
    {
        const char *httpResponse = response.c_str();
        if (SSL_write(ssl, httpResponse, strlen(httpResponse)) < 0)
        {
            std::cerr << "Error al enviar la respuesta HTTPS" << std::endl;
            return -1;
        }
        return 0;
    }
    else
    {
        const char *httpResponse = response.c_str();
        if (send(socket, httpResponse, strlen(httpResponse), 0) < 0)
        {
            std::cerr << "Error al enviar la respuesta HTTP" << std::endl;
            return -1;
        }
        return 0;
    }
}

int __wait_socket(int socket, SSL *ssl)
{

    if (ssl != NULL)
    {
        try
        {
            // Cerrar la conexión SSL y el socket
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(socket);
            // SSL_clear(ssl);
            socket = -1; // Establecer el socket en un valor no válido
            return 0;
        }
        catch (std::exception &e)
        {
            cout << e.what() << "Comunication already closed" << endl;
        }
    }

    if (socket >= 0)
    {
        try
        {
            shutdown(socket, SHUT_WR);
            close(socket);
            socket = -1; // Establecer el socket en un valor no válido
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << "Comunication already closed" << '\n';
            return -1;
        }
    }
    return 0;
}

int HttpServer::__handle_request(int socket, SSL *ssl)
{
    std::string request(UrlEncoding::decodeURIComponent(__recv(ssl, socket)));

    httpHeaders http_headers(request);
    std::cout << http_headers.getRoute() << std::endl;

    auto session_id = Session::IDfromJWT(http_headers.cookies[this->default_session_name]);
    int session_index = __find_match_session(session_id);
    
    Session session = __get_session(session_index);

    // Buscar la ruta correspondiente en el std::vector de rutas
    std::string response;

    if(!idGeneratorJWT.verifyJWT(http_headers.cookies[this->default_session_name])&&session_index!=-1)
    {
       httpProtoResponse response_server;
        
        response_server.length = this->__unauthorized.length();
        response = response_server.defaultUnauthorized() + this->__unauthorized;
        __send_response(ssl, socket, response);
        __wait_socket(socket, ssl);
        return 0;
    }

    std::unordered_map<std::string, std::string> url_params;
    for (const auto &route : this->routes)
    {
        if (__route_contains_params(route.path))
        {
            if (__match_path_with_route(http_headers.getRoute(), route.path, url_params))
            {
                Request arg = Request(url_params, socket, ssl, http_headers, session, http_headers.getRequest());
                response = route.handler(arg);
                if (session.deleted)
                    this->sessions.erase(this->sessions.begin() + session_index);
                else if (session_index == -1)
                    setNewSession(session);
                else if (session_index != -1)
                    this->sessions[session_index] = session;

                __send_response(ssl, socket, __response_create(response, session));

                __wait_socket(socket, ssl);
                return 0;
            }
        }
        else if (route.path == http_headers.getRoute())
        {
            Request arg = Request(url_params, socket, ssl, http_headers, session, http_headers.getRequest());
            response = route.handler(arg);
            if (session.deleted)
                this->sessions.erase(this->sessions.begin() + session_index);
            else if (!session.isEmpty() && session_index == -1)
                setNewSession(session);
            else if (!session.isEmpty() && session_index != -1)
                this->sessions[session_index] = session;

            __send_response(ssl, socket, __response_create(response, session));

            __wait_socket(socket, ssl);
            return 0;
        }
    }

    // encontrar ruta de archivos (si existiera)
    if (response.empty())
    {
        for (const auto &route_file : routesFile)
        {
            std::string::size_type pos = http_headers.getRoute().find(route_file.path);
            if (pos != std::string::npos)
            {
                // Coincidencia encontrada, reemplazar la ruta URL con la ruta local
                std::string localPath = http_headers.getRoute();
                localPath.replace(pos, route_file.path.length(), route_file.path);
                __response_file(ssl, socket, localPath.substr(1), route_file.type);
                __wait_socket(socket, ssl);
                return 0;
            }
        }
    }

    __send_response(ssl, socket, __response_create(response, session));

    __wait_socket(socket, ssl);
    return 0;
}
