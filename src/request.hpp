#pragma once

#include <unordered_map>
#include <vector>

#include "session.hpp"
#include "httpMethods.hpp"

class UrlParams
{
private:
    std::unordered_map<std::string, server_tools::ParamValue> parameters;

public:
    UrlParams(std::unordered_map<std::string, server_tools::ParamValue> vars_f)
        : parameters(vars_f) {}
    UrlParams() : parameters({}) {}

    int size() const
    {
        return parameters.size();
    }

    bool empty() const
    {
        return parameters.empty();
    }

    int indexType(const std::string &key) const
    {
        if (parameters.find(key) == parameters.end())
            return -1;
        return parameters.at(key).index();
    }

    // example: url_params.get<int>("id");
    template <typename T>
    T get(const std::string &key) const
    {
        auto it = parameters.find(key);
        if (it != parameters.end())
        {
            if (std::holds_alternative<T>(it->second))
                return std::get<T>(it->second);
            else
                throw std::runtime_error("Error: type mismatch");
        }
        else
            return T();
    }

    std::string getString(const std::string &key) const
    {
        // if is string return as string, else convert
        auto it = parameters.find(key);
        if (it != parameters.end())
        {
            if (it->second.index() == 3)
                return std::get<std::string>(it->second);
            else
                return std::to_string(std::get<int>(it->second));
        }
        else
            return "";
    }

    int getInt(const std::string &key) const
    {
        // if is string return as string, else convert
        auto it = parameters.find(key);
        if (it != parameters.end())
        {
            switch (it->second.index())
            {
            case 0:
                return std::get<int>(it->second);
                break;
            case 1: // float
                return std::get<float>(it->second);
                break;
            case 2:
                return std::get<bool>(it->second);
                break;
            case 3:
                return std::stoi(std::get<std::string>(it->second));
                break;
            default:
                return std::numeric_limits<int>::quiet_NaN();
                break;
            }
        }
        else
            return std::numeric_limits<int>::quiet_NaN();
    }

    float getFloat(const std::string &key) const
    {
        // if is string return as string, else convert
        auto it = parameters.find(key);
        if (it != parameters.end())
        {
            switch (it->second.index())
            {
            case 0:
                return std::get<int>(it->second);
                break;
            case 1: // float
                return std::get<float>(it->second);
                break;
            case 2:
                return std::get<bool>(it->second);
                break;
            case 3:
                return std::stof(std::get<std::string>(it->second));
                break;
            default:
                return std::numeric_limits<float>::quiet_NaN();
                break;
            }
        }
        else
            return std::numeric_limits<float>::quiet_NaN();
    }

    bool getBool(const std::string &key) const
    {
        // if is string return as string, else convert
        auto it = parameters.find(key);
        if (it != parameters.end())
        {
            switch (it->second.index())
            {
            case 0:
                return std::get<int>(it->second);
                break;
            case 1: // float
                return std::get<float>(it->second);
                break;
            case 2:
                return std::get<bool>(it->second);
                break;
            case 3:
                return std::get<std::string>(it->second) == "true";
                break;
            default:
                return false;
                break;
            }
        }
        else
            return false;
    }

    std::string operator[](const std::string &key) const
    {
        return getString(key);
    }
};

class Request
{

public:
    UrlParams parameters;

    std::string method;
    std::string route;
    std::string query;
    httpHeaders headers;

    Content content;
    std::map<std::string, std::string> form;

    Sessions::Session &session;

    Request(Sessions::Session &session_f)
        : session(session_f) {}

    Request(std::unordered_map<std::string, server_tools::ParamValue> vars_f, httpHeaders method_f, Sessions::Session &session_f, HttpRequest method)
        : parameters(vars_f), headers(method_f), session(session_f), method(method.method), route(method.route), query(method.query)
    {
        if (method.content.isDict())
            form = method.content.getDict();
        content = method.content;
    }
    // Request(std::unordered_map<std::string, std::string> vars_f, httpHeaders method_f, Session& session_f, HttpRequest method)
    //     : parameters(vars_f), headers(method_f), session(session_f), method(method.method), route(method.route), query(method.query) {}
};