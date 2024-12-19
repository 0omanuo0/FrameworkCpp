#pragma once

#include <string>
#include <regex>


namespace server_tools
{

    inline bool _route_contains_params(const std::string &routePath)
    {
        const std::regex paramRegex("<[^>]+>");
        return std::regex_search(routePath, paramRegex);
    }

    inline bool _match_path_with_route(const std::string &path, const std::string &routePath, std::unordered_map<std::string, std::string> &url_params)
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

}