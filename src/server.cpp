
#include "server.hpp"
#include "tools/complementary_server_functions.hpp"
#include "jinjaTemplating/templating.h"

int HttpServer::_find_match_session(std::string id)
{
    for (int i = 0; i < (int)sessions.size(); i++)
        if (sessions[i].getId() == id)
            return i; // Devuelve la posición en el vector
    
    return -1; // Retorna -1 si no se encuentra la sesión
}

Session HttpServer::_get_session(int index){
    if (index >= 0 && index < (int)sessions.size())
        return sessions[index]; // Devuelve la sesión correspondiente al índice
    else{
        auto id = string(idGenerator::generateUUID());
        return Session(id); // Devuelve una sesión vacía si el número está fuera de rango
    }
        
}

Session HttpServer::_set_new_session(Session session){
    this->sessions.push_back(session);
    return session;
}

void HttpServer::_setup_server()
{
    this->loop_ = uvw::Loop::getDefault();
    this->server_ = loop_->resource<uvw::TCPHandle>();
    this->server_->bind(this->ip_, this->port_);

    configureOpenSSL(this->ctx_, this->ssl_context_[0].c_str(), this->ssl_context_[1].c_str());
}

HttpServer::HttpServer(const std::string &ip, int port, const std::string ssl_context[])
    : workerPool_(4, taskQueue_)
{
    this->ip_ = ip;
    this->port_ = port;
    ssl_context_[0] = ssl_context[0];
    ssl_context_[1] = ssl_context[1];
    this->template_render = std::make_shared<Templating>();
    this->template_render->server = this;
}

void _send_response(std::shared_ptr<SSLClient> sslClient, const std::string &response)
{
    std::unique_ptr<char[]> responseData(new char[response.size()]);
    memcpy(responseData.get(), response.data(), response.size());
    sslClient->write(std::move(responseData), response.size());
}

int _send_file(std::shared_ptr<SSLClient> sslClient, const std::string &path, const std::string &type)
{
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
    if(!file.read(buffer.get(), file_size)) // error reading the file
    {
        
        return -1;
    }

    response_serv.addHeader("Content-Type", type);
    response_serv.addHeader("Content-Disposition", "attachment; filename=\"" + realpath.substr(realpath.find_last_of("/") + 1) + "\"");
    response_serv.setIsFile(type, file_size);

    std::string response = response_serv.generateResponse();
    response += std::string(buffer.get(), file_size);

    file.close();

    _send_response(sslClient, response);

    return 0;
}


int HttpServer::_handle_request(std::string request, std::shared_ptr<SSLClient> sslClient)
{
    httpHeaders http_headers(UrlEncoding::decodeURIComponent(request));

    auto session_id = Session::IDfromJWT(http_headers.cookies[this->default_session_name]);
    int session_index = this->_find_match_session(session_id);

    Session session = this->_get_session(session_index);

    if (!idGeneratorJWT.verifyJWT(http_headers.cookies[this->default_session_name]) && session_index != -1)
    {
        auto s = Session();
        Request req(s);
        Response response_server = this->defaults.getUnauthorized(req);
        _send_response(sslClient, response_server.generateResponse());

        this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery() + ", Session expired", "401");

        return 0;
    }

    // Find The route in the routes vector
    int index_route = -1;

    std::unordered_map<std::string, std::string> url_params;
    for (size_t i = 0; i < (size_t)routes.size(); i++)
    {
        const auto &route = routes[i];
        if (server_tools::_route_contains_params(route.path))
        {
            if (server_tools::_match_path_with_route(http_headers.getRoute(), route.path, url_params))
            {
                index_route = i;
                break;
            }
        }
        else if (route.path == http_headers.getRoute())
        {
            index_route = i;
            break;
        }
    }


    if (index_route != -1)
    {
        this->taskQueue_.push([sslClient, this, index_route, session, session_index, url_params, headers=std::move(http_headers)]() {
            // create a copy of the headers because is a const
            auto headers2 = headers;
            auto session_mut = session;
            
            Request arg = Request(url_params, headers2, session_mut, headers2.getRequest());
            auto route = this->routes[index_route];
            server_types::HttpResponse responseHandler;
            try
            {
                responseHandler = route.handler(arg);
            }
            catch (const std::exception &e)
            {
                this->logger_.error("Error while handling the request", e.what());
                auto s = Session();
                Request req(s);
                Response response = this->defaults.getInternalServerError(req);
                _send_response(sslClient, response.generateResponse()); 

                this->logger_.log(headers2.getMethod() + " " + headers2.getRoute() + " " + headers2.getQuery(), "500");
                return 0;
            }

            Response response = std::holds_alternative<string>(responseHandler)
                                    ? Response(std::get<string>(responseHandler))
                                    : std::get<Response>(responseHandler);

            if (session_mut.deleted)
                this->sessions.erase(this->sessions.begin() + session_index);
            else if (session_index == -1)
                this->_set_new_session(session_mut);
            else if (session_index != -1)
                this->sessions[session_index] = session_mut;

            response.addSessionCookie(this->default_session_name, this->idGeneratorJWT.generateJWT(session_mut.toString()));

            auto resCode = std::to_string(response.getResponseCode());
            this->logger_.log(headers2.getMethod() + " " + headers2.getRoute() + " " + headers2.getQuery(), resCode);

            std::string responseStr = response.generateResponse();

            _send_response(sslClient, responseStr);

            return 0;
        });

        return 0;
    }

    for(const auto &route_file : this->routesFile){
        if(route_file.path == http_headers.getRoute()){

            auto error = _send_file(sslClient, route_file.path, route_file.type);
            
            if(error == -1)
            {
                Request arg = Request(url_params, http_headers, session, http_headers.getRequest());
                Response response = this->defaults.getNotFound(arg);
                _send_response(sslClient, response.generateResponse());
                this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery(), "404");
            }
            else if(error == -2)
            {
                Request arg = Request(url_params, http_headers, session, http_headers.getRequest());
                Response response = this->defaults.getInternalServerError(arg);
                _send_response(sslClient, response.generateResponse());
                this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery(), "500");
            }
            this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery(), "200");
            return 0;
        }
    }


    // 404, error
    Request arg = Request(url_params, http_headers, session, http_headers.getRequest());
    Response response = this->defaults.getNotFound(arg);
    _send_response(sslClient, response.generateResponse());
    this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery(), "404");
    
    return 0;
}

void HttpServer::_run_server()
{
    this->server_->on<uvw::ListenEvent>([this](const uvw::ListenEvent &, uvw::TCPHandle &srv)
    {
        auto client = srv.loop().resource<uvw::TCPHandle>();
        srv.accept(*client);
        client->read();

        auto sslClient = std::make_shared<SSLClient>(client, this->ctx_);

        sslClient->onData([sslClient, this](const char *data, std::size_t length) {
            std::string request(data, length);
            this->_handle_request(request, sslClient);
        });

        sslClient->onClose([this]() {
            this->logger_.log("Client disconnected");
        });

        client->on<uvw::ErrorEvent>([this](const uvw::ErrorEvent &event, uvw::TCPHandle &)
            { this->logger_.error("Client error: " + std::string(event.what())); }); 
    });

    this->server_->on<uvw::ErrorEvent>([this](const uvw::ErrorEvent &event, uvw::TCPHandle &)
        { this->logger_.error("Server error: " + std::string(event.what())); });

    this->server_->listen();
    this->logger_.log("Server is listening on " + this->ip_ + ":" + std::to_string(this->port_));
    this->loop_->run();

    SSL_CTX_free(this->ctx_);
    EVP_cleanup();
}

void HttpServer::run()
{
    try
    {
        this->_setup_server();
    }
    catch (const std::exception &ex)
    {
        this->logger_.error("Error: " + std::string(ex.what()));
    }

    try
    {
        this->_run_server();
    }
    catch (const std::exception &ex)
    {
        this->logger_.error("Error: " + std::string(ex.what()));
        if (this->ctx_)
        {
            SSL_CTX_free(this->ctx_);
        }
    }
}

std::string HttpServer::Render(const std::string &route, nlohmann::json data)
{
    return this->template_render->Render(route, data);
}