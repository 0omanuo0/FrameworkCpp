#pragma once

#include <regex>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace server_tools
{
    enum class ParamType
    {
        INT,
        FLOAT,
        BOOL,
        STRING
    };

    struct routeRE
    {
        bool found;
        std::regex regex;
        std::vector<ParamType> param_types;
    };

    using ParamValue = std::variant<int, float, bool, std::string>;

    inline bool is_valid_route(const std::string &routePath)
    {
        // Expresión regular para validar caracteres en la ruta
        const std::regex validRouteRegex(R"(^(?:[\/\w\-.:]+|<\w+(?::\w+)?>)+$)");
        return std::regex_match(routePath, validRouteRegex);
    }

    inline routeRE _route_contains_params(const std::string &routePath)
    {
        if (!is_valid_route(routePath))
        {
            throw std::runtime_error("invalid route, " + routePath);
            return {false, {}, {}};
        }

        const std::regex paramRegex(R"(<(\w+)(?::(\w+))?>)");
        bool found = std::regex_search(routePath, paramRegex);
        if (!found)
        {
            // create the regex for the route as it is
            std::regex routeRegex(routePath);
            return {false, routeRegex, {}};
        }

        std::sregex_iterator i = std::sregex_iterator(routePath.begin(), routePath.end(), paramRegex);
        std::sregex_iterator end = std::sregex_iterator();

        std::string routeRegex = routePath;
        std::vector<ParamType> param_types;

        for (; i != end; ++i)
        {
            std::smatch match = *i;
            std::string full_match = match.str(0); // Coincidencia completa, ej. "<id:int>"
            std::string param_name = match.str(1); // Nombre del parámetro, ej. "id"
            std::string type = match.str(2);       // Tipo del parámetro, ej. "int"

            std::string replacement;

            if (type == "int")
            {
                replacement = R"((\d+))";
                param_types.push_back(ParamType::INT);
            }
            else if (type == "float")
            {
                replacement = R"((\d+\.\d+))";
                param_types.push_back(ParamType::FLOAT);
            }
            else if (type == "bool")
            {
                replacement = R"((true|false|1|0))";
                param_types.push_back(ParamType::BOOL);
            }
            else
            { // Default: string
                replacement = R"(([^/]+))";
                param_types.push_back(ParamType::STRING);
            }

            // Reemplazar la primera ocurrencia del parámetro en routeRegex
            size_t pos = routeRegex.find(full_match);
            if (pos != std::string::npos)
            {
                routeRegex.replace(pos, full_match.length(), replacement);
            }
        }

        return {true, std::regex("^" + routeRegex + "$"), param_types};
    }

    inline bool _match_path_with_route(const std::string &path, const routeRE &route, std::unordered_map<std::string, ParamValue> &url_params)
    {
        std::smatch matches;

        if (!route.found)
            return std::regex_match(path, route.regex);

        if (!std::regex_match(path, matches, route.regex))
            return false;

        const size_t matches_size = matches.size();
        if (matches_size != route.param_types.size() + 1)
            return false;

        // reserve memory for the url_params map
        url_params.reserve(url_params.size() + route.param_types.size());

        // from 1 to matches_size to skip the first match which is the whole path
        for (size_t i = 1; i < matches_size; i++)
        {
            std::string param_name = "param" + std::to_string(i);
            std::string param_value = matches[i].str();

            // stoi, stof, stob, etc. throw exceptions if the conversion fails
            try
            {
                switch (route.param_types[i - 1])
                {
                case ParamType::INT:
                    url_params[param_name] = std::stoi(param_value);
                    break;
                case ParamType::FLOAT:
                    url_params[param_name] = std::stof(param_value);
                    break;
                case ParamType::BOOL:
                    url_params[param_name] = (param_value == "true" || param_value == "1");
                    break;
                case ParamType::STRING:
                    url_params[param_name] = param_value;
                    break;
                }
            }
            catch (...)
            {
                return false;
            }
        }

        return true;
    }

}