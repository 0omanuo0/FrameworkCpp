#ifndef TOOLS_H
#define TOOLS_H

#include <iostream>
#include <vector>
#include <string>
#include <regex>
#include <sstream>
#include <fstream>
#include <unordered_map>

#include "types.h"
#include "json.hpp"
#include "jinjaFunctions.h"
#include "tinyexpr.h"
#include "templating.h"

inline bool is_number(const nlohmann::json &j, std::string key)
{
    if (!j.contains(key))
        return false;
    return j[key].is_number_integer() || j[key].is_number_unsigned() || j[key].is_number_float();
}

inline double stringToNumber(const std::string &str)
{
    char *ptr;
    auto r = std::strtod(str.c_str(), &ptr);
    return !*ptr ? r : std::numeric_limits<double>::quiet_NaN();
}

inline nlohmann::json accessJsonValue(const nlohmann::json &data, const std::string &key)
{
    std::regex re(R"(\.|\[|\])");
    std::sregex_token_iterator iter(key.begin(), key.end(), re, -1);
    std::sregex_token_iterator end;
    nlohmann::json value = data;
    for (; iter != end; ++iter)
    {
        try
        {
            if (iter->str().empty())
                continue; // skip empty strings
            if (iter->str().front() >= '0' && iter->str().front() <= '9')
                value = value[std::stoi(iter->str())];
            else
                value = value[iter->str()];
        }
        catch (const std::exception &e)
        {
            throw std::runtime_error("The key " + key + " is not valid");
        }
    }
    return value;
}

inline void __preprocessExpression(std::string &expression, const nlohmann::json &data);

inline double __evaluateExpression(std::string expression, const nlohmann::json &data)
{
    te_parser parser;
    std::set<std::string> variables;

    parser.set_unknown_symbol_resolver(
        [&variables, data](std::string_view symbol) -> te_type
        {
            variables.insert(std::string(symbol));
            auto expr = std::string(symbol);
            try
            {
                __preprocessExpression(expr, data);
                // ckeck if is a number
                return stringToNumber(expr);
            }
            catch (const std::exception &e)
            {
                auto value = accessJsonValue(data, expr);
                if (value == nullptr)
                    return 0;
                if (value.is_number())
                    return value.get<double>();
                else if (value.is_string()){
                    return stringToNumber(value.get<std::string>());
                }
            }
            return std::numeric_limits<double>::quiet_NaN();
        });

    try
    {
        if (parser.compile(expression)) return parser.evaluate();
        else return std::numeric_limits<double>::quiet_NaN();
    }
    catch(const std::exception& e)
    {
        return std::numeric_limits<double>::quiet_NaN();
    }
}

inline void __preprocessExpression(std::string &expression, const nlohmann::json &data)
{
    // check if the expression has something like (filters or functions)
    // value|length|sum|length|capitalize|lower|upper|first|last|reverse|sort|str|json|join|replace|split|slice|range

    // check if the first or last character is a pipe if so, throw an error
    if (expression.front() == '|' || expression.back() == '|')
        throw std::runtime_error("The expression " + expression + " is not valid");

    const std::regex filter_pattern(R"(([^|]+))");
    // check every filter, the first match is the value and the rest are filters

    std::smatch match;
    std::string value;
    std::vector<std::string> filters;
    if (std::regex_search(expression, match, filter_pattern))
    {
        value = match[1].str();
        std::string filters_str = expression.substr(match[1].length());
        std::regex filter_pattern(R"(\|([^|]+))");
        std::sregex_token_iterator iter(filters_str.begin(), filters_str.end(), filter_pattern, 1);
        std::sregex_token_iterator end;
        for (; iter != end; ++iter)
        {
            filters.push_back(iter->str());
        }
    }

    // evaluate the value with the filters
    nlohmann::json result = accessJsonValue(data, value);

    std::reverse(filters.begin(), filters.end());

    for (auto &filter : filters)
    {
        if (JinjaFunctions::functions.find(filter) != JinjaFunctions::functions.end())
        {
            result = JinjaFunctions::functions.at(filter)(result);
        }
        else
        {
            throw std::runtime_error("The filter " + filter + " is not valid");
        }
    }

    expression = result.dump();
}

inline std::pair<long, long> process_range(const std::string &iterable, const nlohmann::json &data)
{
    const std::regex range_pattern(R"(range\(\s*([^{}])(?:\s*,\s*([^{}]+))?\s*\))");
    std::smatch match;
    long n = -1;
    long m = -1;

    if (std::regex_search(iterable, match, range_pattern))
    {
        if (match[2].str() != "")
        {

            char *p;
            n = strtol(match[1].str().c_str(), &p, 10);
            if (*p)
            {
                if (__evaluateExpression(match[1].str(), data) != std::numeric_limits<double>::quiet_NaN())
                    n = (long)__evaluateExpression(match[1].str(), data);
                else if (is_number(data, match[1].str()))
                    n = data[match[1].str()].get<long>();
                else
                {
                    std::cerr << "Error: the variable " << match[1].str() << " or " << match[2].str() << " is not a number" << std::endl;
                    return std::make_pair(0, 0);
                }
            }
        }

        char *p;
        m = strtol(match[2].str().c_str(), &p, 10);
        if (*p)
        {
            if (__evaluateExpression(match[2].str(), data) != std::numeric_limits<double>::quiet_NaN())
                m = (long)__evaluateExpression(match[2].str(), data);
            else if (is_number(data, match[2].str()))
                m = data[match[2].str()].get<long>();
            else
            {
                std::cerr << "Error: the variable " << match[1].str() << " or " << match[2].str() << " is not a number" << std::endl;
                return std::make_pair(0, 0);
            }
        }
    }

    return std::make_pair(n, m);
}

inline std::unordered_map<std::string, nlohmann::json> convertToMap(const nlohmann::json &data)
{
    std::unordered_map<std::string, nlohmann::json> rmap;

    for (auto it = data.begin(); it != data.end(); ++it)
    {
        rmap[it.key()] = it.value();
    }
    return rmap;
}


#endif // TOOLS_H