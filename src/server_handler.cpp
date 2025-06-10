#include "server.hpp"
#include "tools/complementary_server_functions.hpp"
#include "tools/handler_tools.hpp"

#include <mutex>
#include <future>
#include <fstream>
#include <stdexcept>
#include <filesystem>
#include <algorithm>

// -----------------------------------------------------------------------------
// Route matching helper
// -----------------------------------------------------------------------------
inline int HttpServer::_route_matcher(const std::string &http_route,
                                      std::unordered_map<std::string, server_tools::ParamValue> &url_params)
{
    for (size_t i = 0; i < routes.size(); i++)
    {
        const auto &route = routes[i];
        if (route.contains_params)
        {
            if (server_tools::_match_path_with_route(http_route, route.route_regex, url_params))
            {
                return static_cast<int>(i);
            }
        }
        else if (route.path == http_route)
        {
            return static_cast<int>(i);
        }
    }
    return -1;
}

// -----------------------------------------------------------------------------
// Main request handler for an inbound request
// -----------------------------------------------------------------------------
int HttpServer::_handle_request(std::string request, std::shared_ptr<HttpConnection> conn)
{
    if (!conn || !conn->active())
    {
        return -1; // Invalid or closed client, just bail out
    }

    httpHeaders http_headers(UrlEncoding::decodeURIComponent(request));

    auto &client_data = this->clients[conn->getClient()];
    // More robust check for keep-alive: look for "keep-alive" substring or parse properly
    client_data.keep_alive = (http_headers["Connection"].getString() == "keep-alive");

    // -----------------------------
    // 1) SESSION Handling
    // -----------------------------
    Sessions::Session *session_opt = nullptr;
    if (http_headers.cookies.find(this->sessions_->default_session_name) == http_headers.cookies.end())
    {
        // No existing session cookie, create new session
        session_opt = this->sessions_->generateNewSession();
    }
    else
    {
        // Validate the existing session
        session_opt = this->sessions_->validateSessionCookie(
            http_headers.cookies[this->sessions_->default_session_name]);
    }

    if (!session_opt)
    {
        // Session invalid or expired
        Response response_server = this->defaults.getUnauthorized();
        conn->_send_response(response_server.generateResponse());

        this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() +
                              " " + http_headers.getQuery() + ", Session expired",
                          "401");
        return 0;
    }

    // We take a local copy to avoid pointer issues
    auto session = *session_opt;
    auto session_id = session.getId(); // could be used for logging or debugging

    // -----------------------------
    // 4) Try static file routes first because they are faster (dont use regex)
    // -----------------------------
    if (_handle_static_file(conn, session, http_headers))
    {
        return 0;
    }

    // -----------------------------
    // 4) Route matching
    // -----------------------------
    std::unordered_map<std::string, server_tools::ParamValue> url_params;
    int index_route = _route_matcher(http_headers.getRoute(), url_params);

    // If matched a dynamic route
    if (index_route != -1)
    {
        std::vector<std::string> &methods = routes[index_route].methods;
        if (std::find(methods.begin(), methods.end(), http_headers.getMethod()) == methods.end())
        {

            conn->_send_response(this->defaults.getMethodNotAllowed().generateResponse());

            this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() +
                                  " " + http_headers.getQuery(),
                              "405");
            return 0;
        }

        if (this->routes[index_route].static_route && !this->static_routes[index_route].is_empty)
        {
            Response response_server = this->static_routes[index_route].res;
            conn->_send_response(response_server.generateResponse());
            this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() +
                                  " " + http_headers.getQuery(),
                              std::to_string(response_server.getResponseCode()));
            return 0;
        }

        // Push route handling to the worker queue
        taskQueue_.push([conn, this, route = routes[index_route], session, url_params, headers = std::move(http_headers)]()
                        { this->_handle_route(conn, route, session, url_params, headers); });
        return 0;
    }

    // -----------------------------
    // 5) Public folder
    // -----------------------------
    if (this->public_folder != "")
    {
        if (http_headers.getRoute().substr(1, this->public_folder.length()) == this->public_folder)
        {
            // sanitize route (remove all dangerous characters)
            if (check_dangerous_route(http_headers.getRoute(), this->public_folder)) // return 404
            {
                conn->_send_response(this->defaults.getNotFound().generateResponse());
                this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() +
                                      " " + http_headers.getQuery(),
                                  "404");
                return 0;
            }

            std::string path = this->public_folder + http_headers.getRoute();
            std::string extension = http_headers.getRoute().substr(http_headers.getRoute().find_last_of(".") + 1);
            std::string type;
            if (server_types::content_type.find(extension) != server_types::content_type.end())
                type = server_types::content_type.at(extension);
            else
                type = "application/octet-stream";
            // send to the worker queue
            this->_send_file_worker(conn, http_headers.getRoute(), http_headers.getRoute().substr(1), type, true);

            return 0;
        }
    }

    // -----------------------------
    // 5) No route matched => 404
    // -----------------------------
    conn->_send_response(this->defaults.getNotFound().generateResponse());
    this->logger_.log(http_headers.getMethod() + " " + http_headers.getRoute() +
                          " " + http_headers.getQuery(),
                      "404");
    return 0;
}
