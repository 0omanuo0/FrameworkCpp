#pragma once

#include <uvw.hpp>
#include <zlib.h>
#include <stdexcept>
#include <cstring>
#include <string>
#include <memory>
#include <iostream>
#include <filesystem>


inline std::string compressData(const std::string &data)
{
    // For large data, consider a streaming approach; for demonstration we keep it in-memory.

    z_stream zs;
    std::memset(&zs, 0, sizeof(zs));

    // Using 15 + 16 for gzip encoding, Z_BEST_SPEED or Z_BEST_COMPRESSION can be chosen
    // based on the trade-offs you want to optimize (CPU vs. size).
    if (deflateInit2(&zs,
                     Z_BEST_COMPRESSION,
                     Z_DEFLATED,
                     15 + 16,
                     8,
                     Z_DEFAULT_STRATEGY) != Z_OK)
    {
        throw std::runtime_error("Failed to initialize zlib compression.");
    }

    zs.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(data.data()));
    zs.avail_in = static_cast<uInt>(data.size());

    std::string compressedData;
    compressedData.reserve(data.size() / 2); // Pre-reserve to reduce re-allocs; this is heuristic.

    char outBuffer[8192];
    int ret;
    do
    {
        zs.next_out = reinterpret_cast<Bytef *>(outBuffer);
        zs.avail_out = sizeof(outBuffer);

        ret = deflate(&zs, Z_FINISH);
        if (ret == Z_STREAM_ERROR)
        {
            deflateEnd(&zs);
            throw std::runtime_error("Stream error during compression.");
        }

        // The number of bytes compressed in this iteration
        const size_t have = sizeof(outBuffer) - zs.avail_out;
        compressedData.append(outBuffer, have);
    } while (ret == Z_OK);

    // Clean up
    if (deflateEnd(&zs) != Z_OK && ret != Z_STREAM_END)
    {
        throw std::runtime_error("Error finishing compression with zlib.");
    }

    return compressedData;
}

// inline void _send_response(std::shared_ptr<uvw::TCPHandle> client, const std::string &response)
// {
//     // In some production cases, partial writes need to be handled if the data is large.
//     // uvw can queue writes, but we demonstrate the simpler approach here.
//     if (!client || !client->active())
//     {
//         return; // Client might be closed or invalid
//     }

//     // If you are writing large data, consider chunking or using client->on<uvw::WriteEvent>()
//     // to handle partial writes. For now, we copy all data at once.
//     auto buffer = std::unique_ptr<char[]>(new char[response.size()]);
//     std::memcpy(buffer.get(), response.data(), response.size());

//     client->write(std::move(buffer), response.size());
// }


inline bool check_dangerous_route(const std::string &route, const std::string &base_path)
{
    // Check for absolute path or ".." in the route
    // get the absolute path of the route with the actual path of the running server
    std::filesystem::path absolute_path = std::filesystem::absolute(route.substr(1));
    std::filesystem::path base_path_obj = std::filesystem::absolute(base_path);
    // Check if the absolute path is a subpath of the base path
    if (absolute_path.string().find(base_path_obj.string()) != 0)
    {
        return true; // The route is outside the base path
    }
    // Check for ".." in the route
    return route.find("../") != std::string::npos || route.find("..\\") != std::string::npos;
}