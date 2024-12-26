#include "server.hpp"
#include "tools/complementary_server_functions.hpp"




inline void _send_response(std::shared_ptr<ssl_server::SSLClient> sslClient, const std::string &response)
{
    std::unique_ptr<char[]> responseData(new char[response.size()]);
    memcpy(responseData.get(), response.data(), response.size());
    sslClient->write(std::move(responseData), response.size());
}

inline int _send_file(std::shared_ptr<ssl_server::SSLClient> sslClient, const std::string &path, const std::string &type)
{
    // std::cout << "serving file: " << path << std::endl;
    auto realpath = path;
    if (realpath[0] == '/')
        realpath = realpath.substr(1);
    std::ifstream file(realpath, std::ios::binary);
    Response response_serv("", 200);

    if (!file.is_open() && !file.good()) // not open or not good (probably not found)
        return -1;

    file.seekg(0, std::ios::end);
    auto file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::unique_ptr<char[]> buffer(new char[file_size]);
    if (!file.read(buffer.get(), file_size)) // error reading the file
    {

        return -2;
    }

    response_serv.addHeader("Content-Type", type);
    response_serv.addHeader("Content-Disposition", "attachment; filename=\"" + realpath.substr(realpath.find_last_of("/") + 1) + "\"");
    response_serv.setIsFile(type, file_size);

    std::string response = response_serv.generateResponse();
    response += std::string(buffer.get(), file_size);

    file.close();

    _send_response(sslClient, response);

    // std::cout << "file served" << std::endl;

    return 0;
}


inline int HttpServer::_route_matcher(const std::string &http_route, std::unordered_map<std::string, std::string> &url_params)  {

    for (size_t i = 0; i < (size_t)this->routes.size(); i++)
    {
        const auto &route = this->routes[i];
        if (server_tools::_route_contains_params(route.path))
        {
            if (server_tools::_match_path_with_route(http_route, route.path, url_params))
            {
                return i;
            }
        }
        else if (route.path == http_route)
        {
            return i;
        }
    }
    return -1;
}






int HttpServer::_handle_route(
        std::shared_ptr<ssl_server::SSLClient> sslClient, 
        server_types::Route route, 
        Sessions::Session session, 
        std::unordered_map<std::string, std::string> url_params, 
        httpHeaders http_headers 
    )
{
    Request arg = Request(url_params, http_headers, session, http_headers.getRequest());
    server_types::HttpResponse responseHandler;
    try
    {
        responseHandler = route.handler(arg);
    }
    catch (const std::exception &e)
    {
        this->logger_.error("Error while handling the request", e.what());
        _send_response(sslClient, this->defaults.getInternalServerError().generateResponse()); 

        this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery(), "500");
        return 0;
    }

    Response response = std::holds_alternative<std::string>(responseHandler)
                            ? Response(std::get<std::string>(responseHandler))
                            : std::get<Response>(responseHandler);

    if (session.deleted)
        this->sessions_->erase(session.getId());
    else
        this->sessions_->updateSession(session);

    response.addSessionCookie(this->sessions_->default_session_name, this->sessions_->generateJWT(session.getId()));

    response.addHeader("Connection", "keep-alive");
    response.addHeader("Keep-Alive", "timeout=5, max=100");

    auto resCode = std::to_string(response.getResponseCode());
    std::string responseStr = response.generateResponse();

    _send_response(sslClient, responseStr);
    this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery(), resCode);
    return 0; 
}

int HttpServer::_handle_static_file(std::shared_ptr<ssl_server::SSLClient> sslClient, const server_types::RouteFile &route_file, Sessions::Session session, httpHeaders http_headers){
    auto error = _send_file(sslClient, route_file.path, route_file.type);

    if (error == -1) // 404 file not found
    {
        _send_response(sslClient, this->defaults.getNotFound().generateResponse());
        this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery(), "404");
    }
    else if (error == -2) // 500 internal server error
    {
        _send_response(sslClient, this->defaults.getInternalServerError().generateResponse());
        this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery(), "500");
    }
    this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery(), "200");
    return 0;
}

int HttpServer::_handle_request(std::string request, std::shared_ptr<ssl_server::SSLClient> sslClient)
{
    httpHeaders http_headers(UrlEncoding::decodeURIComponent(request));
    Sessions::Session* session_opt;
    if(http_headers.cookies.empty()){
        session_opt = this->sessions_->generateNewSession();
    }
    else{
        session_opt = this->sessions_->validateSessionCookie(http_headers.cookies[this->sessions_->default_session_name]);
    }
    

    if (!session_opt)
    {
        Response response_server = this->defaults.getUnauthorized();
        _send_response(sslClient, response_server.generateResponse());

        this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery() + ", Session expired", "401");

        return 0;
    }
    auto session = *session_opt;
    auto session_id = session.getId();
    
    // Find The route in the routes vector
    std::unordered_map<std::string, std::string> url_params;
    int index_route = _route_matcher(http_headers.getRoute(), url_params);


    if (index_route != -1)
    {
        this->taskQueue_.push([sslClient, this, route = this->routes[index_route], session, url_params, headers = std::move(http_headers)]()
        {
            this->_handle_route(sslClient, route, session, url_params, headers);
        });

        return 0;
    }

    for (const auto &route_file : this->routesFile)
    {
        if (route_file.path == http_headers.getRoute())
        {
            this->_handle_static_file(sslClient, route_file, session, http_headers);
        }
    }

    // 404, error not found
    _send_response(sslClient, this->defaults.getNotFound().generateResponse());
    this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery(), "404");

    return 0;
}