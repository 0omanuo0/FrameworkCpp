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
    if (data.is_string())
        return data.get<std::string>();
    // if is number convert to string but if is integer convert to int
    else if (data.is_number_integer() || data.is_number_unsigned() || data.is_number_float())
    {
        if (data.is_number_integer())
            return std::to_string(data.get<long>());
        else
            return std::to_string(data.get<double>());
    }
    else
        return data.dump();
}

inline std::string trimm(const std::string &str)
{
    std::string s = str;
    s.erase(0, str.find_first_not_of(" \n\r\t"));
    s.erase(s.find_last_not_of(" \n\r\t") + 1);
    return s;
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
                expr expressionEval(str); // Crea una instancia de 'expr' con la cadena
                expressionEval.set_variables(convert_to_variant_map(data)); // Establece las variables de la expresión
                expressionEval.compile(); // Compila la expresión
                double eval_result = expressionEval.eval().toNumber(); // Convierte el resultado a número
                if (eval_result != std::numeric_limits<double>::quiet_NaN())
                    return static_cast<long>(eval_result);
                if (is_number(data, str)) // Verifica si el valor es un número en 'data'
                    return data[str].get<long>();
                Templating_RenderError("Error: the variable " + str + " is not a number", {}, __builtin_FILE(), __builtin_LINE());
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