#include "server.hpp"
#include "tools/complementary_server_functions.hpp"
#include "tools/handler_tools.hpp"

int HttpServer::_handle_route(std::shared_ptr<HttpConnection> conn,
                              server_types::Route route,
                              Sessions::Session session,
                              std::unordered_map<std::string, server_tools::ParamValue> url_params,
                              httpHeaders http_headers)
{
    Request requestData(url_params, http_headers, session, http_headers.getRequest());
    server_types::HttpResponse responseHandler;

    try
    {
        // Execute the route handler
        responseHandler = route.handler(requestData);
    }
    catch (const std::exception &ex)
    {
        this->logger_.error("Error while handling the request", ex.what());
        conn->_send_response( this->defaults.getInternalServerError().generateResponse());

        this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() +
                              " " + http_headers.getQuery(),
                          "500");
        return 0;
    }

    Response response = std::holds_alternative<std::string>(responseHandler)
                            ? Response(std::get<std::string>(responseHandler))
                            : std::get<Response>(responseHandler);

    // Update session data if necessary
    if (session.deleted)
    {
        this->sessions_->erase(session.getId());
    }
    else
    {
        this->sessions_->updateSession(session);
    }

    // Add session cookie in the response
    response.addSessionCookie(this->sessions_->default_session_name,
                              this->sessions_->generateJWT(session.getId()));

    auto &client_data = this->clients[conn->getClient()];
    if (!client_data.keep_alive)
    {
        response.addHeader("Connection", "close");
    }
    else
    {
        response.addHeader("Connection", "keep-alive");
        response.addHeader("Keep-Alive", "timeout=5, max=100");
    }

    // If compression is negotiated, compress
    auto encoding = http_headers["Accept-Encoding"].isList()
                        ? http_headers["Accept-Encoding"].getList()
                        : std::vector<std::string>();

    if (std::find(encoding.begin(), encoding.end(), "gzip") != encoding.end())
    {
        try
        {
            auto compressed = compressData(response.getMessage());
            response.addHeader("Content-Encoding", "gzip");
            response.setMessage(std::move(compressed));
        }
        catch (const std::exception &ex)
        {
            // If compression fails, we can still send uncompressed data, just log an error.
            this->logger_.error("Failed to compress route response", ex.what());
        }
    }

    auto resCode = std::to_string(response.getResponseCode());
    std::string responseStr = response.generateResponse();

    auto rindex = route.index;
    if (this->routes[rindex].static_route && this->static_routes[rindex].is_empty)
    {
        this->static_routes[rindex] = {false, response};
    }

    conn->_send_response(responseStr);

    // If keep-alive is disabled, close the connection
    // if (!client_data.keep_alive) {
    //     client->close();
    // }

    this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() + " " +
                          http_headers.getQuery(),
                      resCode);

    return 0;
}