#include "server.h"
// include time for the current time
#include <ctime>
#include <unordered_map>

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

std::string HttpServer::__recv(SSL *ssl, int socket)
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
            logger.warning("Neither SSL nor socket available");
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
                logger.warning("Error reading the request", strerror(errno));
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

int HttpServer::__response_file(SSL *ssl, int socket, const std::string &path, const std::string &type)
{
    std::vector<std::string> data_to_send = std::vector<std::string>();
    Response response_serv("", 200);

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open() && !file.good())
    {
        logger.warning("Error opening file", std::to_string(404));
        Response not_found = Response(this->__not_found, 404);
        __send_response(ssl, socket, not_found.generateResponse());
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
        logger.warning("Error reading file", std::to_string(404));
        Response not_found = Response(this->__not_found, 404);
        __send_response(ssl, socket, not_found.generateResponse());
        return -1;
    }

    // Construir la respuesta HTTP con el encabezado adecuado

    response_serv.addHeader("Content-Type", type);
    response_serv.addHeader("Content-Disposition", "attachment; filename=\"" + path.substr(path.find_last_of("/") + 1) + "\"");
    response_serv.setIsFile(type, fileSize);

    data_to_send.push_back(response_serv.generateResponse());
    data_to_send.push_back(std::string(buffer_f.begin(), buffer_f.end()));
    auto resCode = std::to_string(response_serv.getResponseCode());
    logger.log("GET " + path, resCode);
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
            logger.warning("Error while sending the HTTP header", strerror(errno));
            return -1;
        }

        if (SSL_write(ssl, response[1].c_str(), response[1].size()) < 0)
        {
            logger.warning("Error while sending the file content", strerror(errno));
            return -1;
        }
    }
    else
    {
        // Enviar el encabezado y el contenido del archivo al cliente
        if (send(socket, response[0].c_str(), response[0].size(), 0) < 0)
        {
            logger.warning("Error while sending the HTTP header", strerror(errno));
            return -1;
        }

        if (send(socket, response[1].c_str(), response[1].size(), 0) < 0)
        {
            logger.warning("Error while sending the file content", strerror(errno));
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
            logger.warning("Error sendind the HTTPS response", strerror(errno));
            return -1;
        }
        return 0;
    }
    else
    {
        const char *httpResponse = response.c_str();
        if (send(socket, httpResponse, strlen(httpResponse), 0) < 0)
        {
            logger.warning("Error sendind the HTTP response", strerror(errno));

            return -1;
        }
        return 0;
    }
}

int HttpServer::__wait_socket(int socket, SSL *ssl)
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
            logger.warning("Comunication already closed", e.what());
            return -1;
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
            logger.warning("Comunication already closed", e.what());
            return -1;
        }
    }
    return 0;
}

int HttpServer::__handle_request(int socket, SSL *ssl)
{
    std::string request(UrlEncoding::decodeURIComponent(__recv(ssl, socket)));

    httpHeaders http_headers(request);

    auto session_id = Session::IDfromJWT(http_headers.cookies[this->default_session_name]);
    int session_index = __find_match_session(session_id);

    Session session = __get_session(session_index);

    /////////////////////////////////////////////
    // print the request method, route and query as [time] METHOD route query

    // Buscar la ruta correspondiente en el std::vector de rutas
    int indexRoute = -1;

    if (!idGeneratorJWT.verifyJWT(http_headers.cookies[this->default_session_name]) && session_index != -1)
    {
        Response response_server(this->__unauthorized, 401);
        logger.log(http_headers.getMethod() + " " + http_headers.getRoute(), http_headers.getQuery() + "401");

        __send_response(ssl, socket, response_server.generateResponse());
        __wait_socket(socket, ssl);
        return 0;
    }

    std::unordered_map<std::string, std::string> url_params;
    for (int i = 0; i < routes.size(); i++)
    {
        const auto &route = routes[i];
        if (__route_contains_params(route.path))
        {
            if (__match_path_with_route(http_headers.getRoute(), route.path, url_params))
            {
                indexRoute = i;
                break;
            }
        }
        else if (route.path == http_headers.getRoute())
        {
            indexRoute = i;
            break;
        }
    }

    if (indexRoute != -1)
    {
        Request arg = Request(url_params, socket, ssl, http_headers, session, http_headers.getRequest());
        auto responseHandler = routes[indexRoute].handler(arg);
        Response response = std::holds_alternative<string>(responseHandler)
                                ? Response(std::get<string>(responseHandler))
                                : std::get<Response>(responseHandler);

        if (session.deleted)
            this->sessions.erase(this->sessions.begin() + session_index);
        else if (session_index == -1)
            setNewSession(session);
        else if (session_index != -1)
            this->sessions[session_index] = session;

        response.addSessionCookie(this->default_session_name, this->idGeneratorJWT.generateJWT(session.toString()));

        auto resCode = std::to_string(response.getResponseCode());
        logger.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery(), resCode);
        __send_response(ssl, socket, response.generateResponse());

        __wait_socket(socket, ssl);
        return 0;
    }

    // encontrar ruta de archivos (si existiera)

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

    Response notFound(this->__not_found, 404);
    auto resCode = std::to_string(notFound.getResponseCode());
    logger.log(http_headers.getMethod() + " " + http_headers.getRoute(), http_headers.getQuery() + " " + resCode);
    __send_response(ssl, socket, notFound.generateResponse());

    __wait_socket(socket, ssl);
    return 0;
}
