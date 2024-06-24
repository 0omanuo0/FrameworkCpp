#ifndef JINJAFUNCTIONS_H
#define JINJAFUNCTIONS_H

#include "json.hpp"
#include <map>
#include <functional>
#include <algorithm>
#include <cctype>

using Json = nlohmann::json;

namespace JinjaFunctions {
    inline Json length(const Json &data)
    {
        return data.size();
    }
    inline Json sum(const Json &data)
    {
        if (data.is_array())
        {
            double sum = 0;
            for (auto &el : data)
                sum += el.get<double>();
            return sum;
        }
        return 0;
    }
    inline Json capitalize(const Json &data)
    {
        std::string str;

        if (data.is_string()) str = data.get<std::string>();
        else if (data.is_array() || data.is_object()) str = data.dump();
        else return nullptr;

        if (!str.empty())
            str[0] = std::toupper(str[0]);
        return str;
    }
    inline Json lower(const Json &data)
    {
        std::string str;

        if (data.is_string()) str = data.get<std::string>();
        else if (data.is_array() || data.is_object()) str = data.dump();
        else return nullptr;

        std::transform(str.begin(), str.end(), str.begin(), ::tolower);
        return str;
    }
    inline Json upper(const Json &data)
    {
        std::string str;

        if (data.is_string()) str = data.get<std::string>();
        else if (data.is_array() || data.is_object()) str = data.dump();
        else return nullptr;

        std::transform(str.begin(), str.end(), str.begin(), ::toupper);
        return str;

    }
    inline Json first(const Json &data)
    {
        if (data.is_array() && !data.empty())
            return data.front();
        else if (data.is_string() && !data.empty())
            return std::string(1, data.get<std::string>()[0]);
        else if (data.is_object() && !data.empty())
            return data.begin().value();
        return nullptr;
    }
    inline Json last(const Json &data)
    {
        if (data.is_array() && !data.empty())
            return data.back();
        else if (data.is_string() && !data.empty())
            return std::string(1, data.get<std::string>().back());
        else if (data.is_object() && !data.empty())
            return std::prev(data.end()).value();
        return nullptr;
    }
    inline Json reverse(Json data) // data should be taken by value to modify it directly
    {
        if (data.is_array())
        {
            std::reverse(data.begin(), data.end());
            return data;
        }
        else if (data.is_string())
        {
            std::string str = data.get<std::string>();
            std::reverse(str.begin(), str.end());
            return str;
        }
        return nullptr;
    }
    inline Json sort(Json data) // data should be taken by value to modify it directly
    {
        if (data.is_array())
        {
            std::sort(data.begin(), data.end());
            return data;
        }
        return nullptr;
    }
    inline Json str(const Json &data)
    {
        return data.dump();
    }
    inline Json join(const Json &data)
    {
        if (data.is_array())
        {
            std::string result;
            for (size_t i = 0; i < data.size(); ++i)
            {
                result += data[i].get<std::string>();
                if (i != data.size() - 1)
                    result += ", ";
            }
            return result;
        }
        return nullptr;
    }

    const std::map<std::string, std::function<Json(const Json &)>> functions = {
        {"length", length},
        {"sum", sum},
        {"capitalize", capitalize},
        {"lower", lower},
        {"upper", upper},
        {"first", first},
        {"last", last},
        {"reverse", reverse},
        {"sort", sort},
        {"str", str},
        {"join", join}
    };
}

#endif // JINJAFUNCTIONS_H
