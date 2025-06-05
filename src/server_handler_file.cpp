#include "server.hpp"
#include "tools/complementary_server_functions.hpp"
#include "tools/handler_tools.hpp"

// -----------------------------------------------------------------------------
// 3) Worker function to read & optionally compress a file, then respond
// -----------------------------------------------------------------------------
void HttpServer::_send_file_worker(const std::shared_ptr<HttpConnection> &conn,
                                   const std::string &path,
                                   const std::string &realPath,
                                   const std::string &type,
                                   bool isCompressible)
{
    // Offload the blocking file I/O and compression to a worker thread.
    taskQueue_.push(
        [this, conn, realPath, path, type, isCompressible]()
        {
            int errorCode = 0;
            std::vector<char> fileData;
            std::string headers;

            // -----------------------------
            // 3.1) Blocking file read
            // -----------------------------
            if (!std::filesystem::exists(realPath))
            {
                errorCode = -1; // File not found
            }
            else
            {
                std::ifstream file(realPath, std::ios::binary);
                if (!file.is_open())
                {
                    errorCode = -1; // Can't open file
                }
                else
                {
                    file.seekg(0, std::ios::end);
                    std::streampos fileSize = file.tellg();
                    file.seekg(0, std::ios::beg);

                    // For large files, consider streaming or memory-mapping,
                    // not reading all into memory. Example only:
                    try
                    {
                        fileData.resize(static_cast<size_t>(fileSize));
                        if (!file.read(fileData.data(), fileSize))
                        {
                            errorCode = -2; // Error reading file
                        }
                    }
                    catch (const std::bad_alloc &ex)
                    {
                        errorCode = -2; // Out of memory, for example
                    }
                    file.close();
                }
            }

            // -----------------------------
            // 3.2) Optionally compress
            // -----------------------------
            if (errorCode == 0 && isCompressible && !fileData.empty())
            {
                try
                {
                    std::string uncompressed(fileData.begin(), fileData.end());
                    std::string compressed = compressData(uncompressed);
                    fileData.assign(compressed.begin(), compressed.end());
                }
                catch (const std::exception &ex)
                {
                    // If compression fails, log it, but let's attempt to send uncompressed
                    this->logger_.error("Compression Error", ex.what());
                }
            }

            // -----------------------------
            // 3.3) Prepare HTTP headers
            // -----------------------------
            if (errorCode == 0)
            {
                Response response("", 200);
                response.addHeader("Content-Type", type);

                // If it's a download, set content-disposition
                response.addHeader("Content-Disposition",
                                   "attachment; filename=\"" +
                                       realPath.substr(realPath.find_last_of("/") + 1) + "\"");

                // CACHE DIRECTIVES
                if (this->enable_cache)
                {
                    response.addHeader("Cache-Control", "public, max-age=" + std::to_string(this->max_age_cache));
                }

                // Set content length based on final fileData size
                response.setIsFile(type, fileData.size());

                // Indicate compression if used
                if (isCompressible)
                {
                    response.addHeader("Content-Encoding", "gzip");
                }

                headers = response.generateResponse();
            }

            // store in cache
            if (errorCode == 0 && this->enable_cache)
            {
                this->file_cache_.put(realPath, fileData);
            }

            // -----------------------------
            // 3.4) Send back results via uvw::AsyncHandle
            // -----------------------------
            auto async = conn->loop().resource<uvw::AsyncHandle>();
            auto resultData = std::make_shared<std::tuple<int, std::string, std::vector<char>>>(
                errorCode, headers, fileData);

            // The callback that runs on the event loop thread
            async->on<uvw::AsyncEvent>(
                [this, conn, resultData, async, path](const uvw::AsyncEvent &, uvw::AsyncHandle &)
                {
                    if (!conn || !conn->active())
                    {
                        async->close();
                        return;
                    }

                    int error;
                    std::string headers;
                    std::vector<char> fileData;
                    std::tie(error, headers, fileData) = *resultData;

                    if (error == -1)
                    {
                        conn->_send_response(this->defaults.getNotFound().generateResponse());
                        this->logger_.log("File not found: " + path, "404");
                    }
                    else if (error == -2)
                    {
                        conn->_send_response(this->defaults.getInternalServerError().generateResponse());
                        this->logger_.log("Error reading file: " + path, "500");
                    }
                    else
                    {
                        // Send headers
                        conn->_send_response(headers);
                        // Then send file content. For large files, consider chunking or partial writes.
                        conn->asyncWrite(fileData.data(), fileData.size());

                        this->logger_.log("GET " + path, "200");
                    }

                    async->close(); // Clean up the async handle
                });

            // Trigger the callback on the main loop
            async->send();
        });
}

int HttpServer::_handle_static_file(std::shared_ptr<HttpConnection> conn,
                                    Sessions::Session session,
                                    httpHeaders http_headers)
{
    const server_types::RouteFile *route_file = nullptr;

    for (const auto &file : routesFile)
    {
        if (file.path == http_headers.getRoute())
        {
            route_file = &file;
            break;
        }
    }

    if (!route_file)
    {
        return 0;
    }

    auto encoding = http_headers["Accept-Encoding"].getList();

    // Only compress if it’s not marked as forced-download and if gzip is available
    bool canCompress = (route_file->type != "application/force-download") &&
                       (std::find(encoding.begin(), encoding.end(), "gzip") != encoding.end());

    canCompress = canCompress && route_file->type.substr(0, 6) != "image/";
    
    std::string realPath = route_file->path;
    if (!this->enable_cache || !realPath.empty() && realPath.front() == '/')
        realPath = realPath.substr(1);

    if (!this->file_cache_.isInCache(realPath))
    {
        _send_file_worker(conn, route_file->path, realPath, route_file->type, canCompress);
        return 1;
    }

    auto async = conn->loop().resource<uvw::AsyncHandle>();
    auto cachedData = this->file_cache_.get(realPath);

    async->on<uvw::AsyncEvent>(
        [this, conn, cachedData, async, type = route_file->type, isCompressible = canCompress, realPath](const uvw::AsyncEvent &, uvw::AsyncHandle &)
        {
            if (!conn || !conn->active())
            {
                async->close();
                return;
            }

            if (cachedData)
            {
                Response response("", 200);
                response.addHeader("Content-Type", type);

                // If it's a download, set content-disposition
                response.addHeader("Content-Disposition",
                                   "attachment; filename=\"" +
                                       realPath.substr(realPath.find_last_of("/") + 1) + "\"");

                // CACHE DIRECTIVES
                if (this->enable_cache)
                {
                    response.addHeader("Cache-Control", "public, max-age=" + std::to_string(this->max_age_cache));
                }

                // Set content length based on final fileData size
                response.setIsFile(type, cachedData->size());

                // Indicate compression if used
                if (isCompressible)
                {
                    response.addHeader("Content-Encoding", "gzip");
                }

                std::string headers = response.generateResponse();
                conn->_send_response(headers);

                auto data = std::make_shared<std::vector<char>>(*cachedData);
                conn->asyncWrite(data->data(), data->size());
                this->logger_.log("GET /" + realPath,
                      "200");
            }
            else
            {
                conn->_send_response(this->defaults.getNotFound().generateResponse());
            }

            async->close(); // Clean up the async handle
        });

    async->send();
    return 1;
}