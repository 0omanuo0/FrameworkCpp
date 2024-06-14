

#ifndef ENCODE_H_
#define ENCODE_H_

#pragma once
#include <string>
#include <regex>
#include "base64.h"

class UrlEncoding
{
private:
    static std::string remove_base64_padding(const std::string &base64_str)
    {
        size_t padding_pos = base64_str.find('.');
        if (padding_pos != std::string::npos)
        {
            return base64_str.substr(0, padding_pos);
        }
        return base64_str;
    }

public:
    static std::string encodeURIbase64(const std::string &in) { return remove_base64_padding(base64_encode(in, true)); }
    static std::string decodeURIbase64(const std::string &in) { return base64_decode(in); }

    static std::string decodeURIComponent(const std::string &url)
    {
        std::ostringstream decoded;
        for (std::size_t i = 0; i < url.length(); ++i)
        {
            if (url[i] == '%' && i + 2 < url.length())
            {
                char hex1 = url[i + 1];
                char hex2 = url[i + 2];
                if (isxdigit(hex1) && isxdigit(hex2))
                {
                    std::istringstream hexStream(std::string() + hex1 + hex2);
                    int hexValue = 0;
                    hexStream >> std::hex >> hexValue;
                    decoded << static_cast<char>(hexValue);
                    i += 2;
                }
                else
                    decoded << url[i];
            }
            else if (url[i] == '+')
                decoded << ' ';
            else
                decoded << url[i];
        }
        return decoded.str();
    }

    static std::string encodeURIComponent(const std::string &input)
    {
        std::string encoded;
        const char *hex = "0123456789ABCDEF";

        for (char c : input)
        {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
                encoded += c;
            else if (c == ' ')
                encoded += '+';
            else
            {
                encoded += '%';
                encoded += hex[c >> 4];
                encoded += hex[c & 15];
            }
        }

        return encoded;
    }
};

#endif