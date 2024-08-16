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

inline std::string jsonToString(const nlohmann::json &data)
{
    if (data.is_string()) return data.get<std::string>();
    // if is number convert to string but if is integer convert to int
    else if (data.is_number_integer() || data.is_number_unsigned() || data.is_number_float())
    {
        if (data.is_number_integer())
            return std::to_string(data.get<long>());
        else
            return std::to_string(data.get<double>());
    }
    else return data.dump();
}

inline std::string trimm(const std::string &str)
{
    std::string s = str;
    s.erase(0, str.find_first_not_of(" \n\r\t"));
    s.erase(s.find_last_not_of(" \n\r\t") + 1);
    return s;
}

inline nlohmann::json accessJsonValue(const nlohmann::json &data, const std::string &key)
{
    std::regex pattern(R"(([^.\[\]]+)|(\[.*?\]))");
    auto cp = trimm(key);
    std::regex_iterator<std::string::iterator> iter(cp.begin(), cp.end(), pattern);
    std::regex_iterator<std::string::iterator> end;

    nlohmann::json value = data;
    for (; iter != end; ++iter)
    {
        try
        {
            if (!iter->str(1).empty())
            {
                auto t = iter->str(1);
                if (t.front() >= '0' && t.front() <= '9')
                    value = value[std::stoi(t)];
                else
                    value = value[t];
            }
            else if(!iter->str(2).empty())
            {
                auto t = iter->str(2);
                t = t.substr(1, t.size() - 2);
                if (t.front() >= '0' && t.front() <= '9')
                    value = value[std::stoi(t)];
                else{
                    auto g = accessJsonValue(data, t);
                    if(g.is_number_integer() || g.is_number_unsigned() || g.is_number_float()||g.is_number())
                        value = value[g.get<long>()];
                    else if(g.is_string())
                        value = value[g.get<std::string>()];
                    else
                        throw std::runtime_error("The key " + key + " is not valid");

                }
            }
        }
        catch (const std::exception &e)
        {
            auto dataa = data.dump();
            // std::cout << dataa << std::endl;
            throw std::runtime_error("The key " + key + " is not valid");
        }
    }
    return value;
}

struct FilterData{
    std::string value;
    std::vector<std::string> filters;
};

inline FilterData getFilters(const std::string &expression){
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
            filters.push_back(trimm(iter->str()));
        }
    }
    return {value, filters};
}


inline nlohmann::json applyFilters(const std::string &value, const std::vector<std::string> &filters, const nlohmann::json &data)
{
    nlohmann::json result = data;

    std::vector<std::string> filters_reversed = filters;

    std::reverse(filters_reversed.begin(), filters_reversed.end());

    for (auto &filter : filters_reversed)
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
    return result;
}

inline void __preprocessExpression(std::string &expression, const nlohmann::json &data){
    // get the value and the filters
    FilterData filterData = getFilters(expression);
    expression = filterData.value;
    auto filters = filterData.filters;

    // evaluate the value with the filters
    nlohmann::json result = accessJsonValue(data, expression);
    result = applyFilters(expression, filters, data);

    // convert the result to string
    expression = jsonToString(result);
}

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


inline std::pair<long, long> process_range(const std::string &iterable, const nlohmann::json &data)
{
    // Define el patrón regex para coincidir con la expresión 'range(n, m)'
    const std::regex range_pattern(R"(range\(\s*([^{,}]+)(?:\s*,\s*([^{,}]+))?\s*\))");
    std::smatch match;
    long n = -1, m = -1;

    // Si el patrón regex encuentra una coincidencia en la cadena 'iterable'
    if (std::regex_search(iterable, match, range_pattern))
    {
        // Define una lambda para analizar y evaluar cada valor encontrado
        auto parse_value = [&data](const std::string &str) -> long
        {
            char *p;
            long val = strtol(str.c_str(), &p, 10); // Intenta convertir la cadena a número
            if (*p)                                 // Si no es un número puro
            {
                double eval_result = __evaluateExpression(str, data); // Intenta evaluar la expresión
                if (eval_result != std::numeric_limits<double>::quiet_NaN())
                    return static_cast<long>(eval_result);
                if (is_number(data, str)) // Verifica si el valor es un número en 'data'
                    return data[str].get<long>();
                std::cerr << "Error: the variable " << str << " is not a number" << std::endl;
                return -1; // Retorna 0 si no se puede evaluar como número
            }
            return val; // Retorna el valor convertido
        };

        n = parse_value(match[1].str());     // Analiza el primer valor
        if (match[2].matched)                // Si hay un segundo valor
            m = parse_value(match[2].str()); // Analiza el segundo valor
        else
        {
            m = n; // Si no hay segundo valor, asigna el valor de 'n'
            n = 0;
        }
    }

    return std::make_pair(n, m); // Retorna el par de valores (n, m)
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