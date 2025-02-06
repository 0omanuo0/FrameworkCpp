#include "server.hpp"
#include "tools/complementary_server_functions.hpp"

std::string compressData(const std::string& data) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    if (deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        throw std::runtime_error("Error al inicializar la compresión zlib.");
    }

    zs.next_in = (Bytef*)data.data();
    zs.avail_in = data.size();

    int ret;
    char buffer[8192];
    std::string compressedData;

    do {
        zs.next_out = reinterpret_cast<Bytef*>(buffer);
        zs.avail_out = sizeof(buffer);

        ret = deflate(&zs, Z_FINISH);

        if (compressedData.size() < zs.total_out) {
            compressedData.append(buffer, zs.total_out - compressedData.size());
        }
    } while (ret == Z_OK);

    deflateEnd(&zs);

    if (ret != Z_STREAM_END) {
        throw std::runtime_error("Error durante la compresión zlib.");
    }

    return compressedData;
}

inline void _send_response(std::shared_ptr<uvw::TCPHandle> client, const std::string &response)
{
    std::unique_ptr<char[]> responseData(new char[response.size()]);
    memcpy(responseData.get(), response.data(), response.size());
    client->write(std::move(responseData), response.size());
}



//////////////////////////////////////////////////////////////////////////////// 
void HttpServer::_send_file_worker(const std::shared_ptr<uvw::TCPHandle>& client,
                                     const std::string &path,
                                     const std::string &type,
                                     bool isCompressible)
{
    // Offload the blocking file I/O and (optional) compression work to your worker pool.
    this->taskQueue_.push([this, client, path, type, isCompressible]() {
        std::string realPath = path;
        if (!realPath.empty() && realPath.front() == '/')
            realPath = realPath.substr(1);

        int errorCode = 0;
        std::vector<char> fileData;
        std::string headers;

        // Blocking file read:
        std::ifstream file(realPath, std::ios::binary);
        if (!file.is_open()) {
            errorCode = -1;  // File not found.
        } else {
            file.seekg(0, std::ios::end);
            auto fileSize = file.tellg();
            file.seekg(0, std::ios::beg);
            fileData.resize(fileSize);
            if (!file.read(fileData.data(), fileSize)) {
                errorCode = -2;  // Error reading file.
            }
            file.close();
        }

        // Optionally compress data if required:
        if (errorCode == 0 && isCompressible) {
            std::string uncompressed(fileData.begin(), fileData.end());
            std::string compressed = compressData(uncompressed);
            fileData.assign(compressed.begin(), compressed.end());
        }

        // If no errors, prepare HTTP headers.
        if (errorCode == 0) {
            Response response("", 200);
            response.addHeader("Content-Type", type);
            response.addHeader("Content-Disposition", "attachment; filename=\"" +
                                   realPath.substr(realPath.find_last_of("/") + 1) + "\"");
            response.setIsFile(type, fileData.size());
            if (isCompressible)
                response.addHeader("Content-Encoding", "gzip");
            headers = response.generateResponse();
        }

        // Create an async handle to post a callback on the main event loop thread.
        auto async = client->loop().resource<uvw::AsyncHandle>();

        // Package up our result in a shared pointer to ensure lifetime safety.
        auto resultData = std::make_shared<std::tuple<int, std::string, std::vector<char>>>(errorCode, headers, fileData);

        async->on<uvw::AsyncEvent>([this, client, resultData, async, path](const uvw::AsyncEvent &, uvw::AsyncHandle &) {
            int error;
            std::string headers;
            std::vector<char> fileData;
            std::tie(error, headers, fileData) = *resultData;

            // Send the appropriate response based on error code.
            if (error == -1) {
                _send_response(client, this->defaults.getNotFound().generateResponse());
                this->logger_.log("File not found", "404");
            } else if (error == -2) {
                _send_response(client, this->defaults.getInternalServerError().generateResponse());
                this->logger_.log("Error reading file", "500");
            } else {
                _send_response(client, headers);
                client->write(fileData.data(), fileData.size());
                this->logger_.log("GET " + path, "200");
            }
            async->close(); // Clean up the async handle.
        });

        // Trigger the async handle, scheduling the callback on the main loop.
        async->send();
    });
}


inline int HttpServer::_route_matcher(const std::string &http_route, std::unordered_map<std::string, std::string> &url_params)
{

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
    std::shared_ptr<uvw::TCPHandle> client,
    server_types::Route route,
    Sessions::Session session,
    std::unordered_map<std::string, std::string> url_params,
    httpHeaders http_headers)
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
        _send_response(client, this->defaults.getInternalServerError().generateResponse());

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

    auto &client_data = this->clients[client.get()];
    if (!client_data.keep_alive)
        response.addHeader("Connection", "close");
    else
    {
        response.addHeader("Connection", "keep-alive");
        response.addHeader("Keep-Alive", "timeout=5, max=100");
    }

    // if compression is enabled, compress the response
    auto encoding = http_headers["Accept-Encoding"].isList() ? http_headers["Accept-Encoding"].getList() : std::vector<std::string>();
    if(std::find(encoding.begin(), encoding.end(), "gzip") != encoding.end()){
        response.addHeader("Content-Encoding", "gzip");
        response.setMessage(compressData(response.getMessage()));
    }

    auto resCode = std::to_string(response.getResponseCode());
    std::string responseStr = response.generateResponse();

    _send_response(client, responseStr);
    if(!client_data.keep_alive)
        client->close();

    this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery(), resCode);
    return 0;
}

int HttpServer::_handle_static_file(std::shared_ptr<uvw::TCPHandle> client, Sessions::Session session, httpHeaders http_headers)
{

    const server_types::RouteFile *route_file = nullptr;

    for (const auto &file : this->routesFile)
    {
        if (file.path == http_headers.getRoute())
        {
            route_file = &file;
            break;
        }
    }

    if (!route_file)
        return 0;

    auto encoding = http_headers["Accept-Encoding"].getList();


    // auto error = _send_file(client, route_file->path, route_file->type, std::find(encoding.begin(), encoding.end(), "gzip") != encoding.end());

    bool CanCompress = (route_file->type != "application/force-download") && (std::find(encoding.begin(), encoding.end(), "gzip") != encoding.end());

    _send_file_worker(client, route_file->path, route_file->type, CanCompress);

    return 1;
}

int HttpServer::_handle_request(std::string request, std::shared_ptr<uvw::TCPHandle> client)
{
    httpHeaders http_headers(UrlEncoding::decodeURIComponent(request));

    auto &client_data = this->clients[client.get()];
    client_data.keep_alive = http_headers["Connection"].getString() == "keep-alive";

    // SESSION
    // Check if the session is valid
    Sessions::Session *session_opt;
    if (http_headers.cookies.empty())
    {
        session_opt = this->sessions_->generateNewSession();
    }
    else
    {
        session_opt = this->sessions_->validateSessionCookie(http_headers.cookies[this->sessions_->default_session_name]);
    }

    if (!session_opt)
    {
        Response response_server = this->defaults.getUnauthorized();
        _send_response(client, response_server.generateResponse());

        this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery() + ", Session expired", "401");

        return 0;
    }
    auto session = *session_opt;
    auto session_id = session.getId();

    // ROUTES
    // Find The route in the routes vector
    std::unordered_map<std::string, std::string> url_params;
    int index_route = _route_matcher(http_headers.getRoute(), url_params);

    if (index_route != -1)
    {
        // check if the method is allowed
        std::vector<std::string> &methods = this->routes[index_route].methods;
        if (std::find(methods.begin(), methods.end(), http_headers.getMethod()) == methods.end())
        {
            _send_response(client, this->defaults.getMethodNotAllowed().generateResponse());
            this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery(), "400");
            return 0;
        }

        this->taskQueue_.push([client, this, route = this->routes[index_route], session, url_params, headers = std::move(http_headers)]()
                              { this->_handle_route(client, route, session, url_params, headers); });

        return 0;
    }

    if (HttpServer::_handle_static_file(client, session, http_headers))
    {
        return 0;
    }

    // 404, error not found
    _send_response(client, this->defaults.getNotFound().generateResponse());
    this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " + http_headers.getQuery(), "404");

    return 0;
}