#pragma once

#include "tools/idGenerator.h"
#include <string.h>
#include <unordered_map>
#include <vector>
#include <sstream>


using namespace std;

inline std::vector<std::string> splitString(const std::string &str, char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream ss(str);

    while (std::getline(ss, token, delimiter))
    {
        tokens.push_back(token);
    }

    return tokens;
}

class Session
{
private:
    string id;
    unordered_map<string, string> values;

public:
    bool create;
    bool deleted = false;
    bool isEmpty() { return id == ""; }
    void addValue(string key, string value) { values.insert(make_pair(key, value)); }
    void modifyValue(string key, string value) { values[key] = value; }
    void removeValue(string key) { values.erase(key); }

    string getId() { return id; }

    void createSession()
    {
        if (isEmpty())
        {
            // idGenerator::generateUUID, but in cstring
            id = idGenerator::generateUUID();
            create = true;
        }
    }
    void destroySession() { deleted = true; }
    string &operator[](string key)
    {
        return values[key];
    }
    // convert to string as json
    string toString()
    {
        string result = "{";
        result += "\"id\":\"" + string(id) + "\",";
        for (auto &i : values)
            result += "\"" + i.first + "\":\"" + i.second + "\",";
        result.pop_back();
        result += "}";
        return result;
    }

    static string IDfromJWT(const string &jwt)
    {
        vector<string> parts = splitString(jwt, '.');
        if (parts.size() < 2)
            return "";

        if(parts[1].empty())
            return "";
        if (parts[1].size() % 4 != 0)
            parts[1].append(4 - parts[1].size() % 4, '.');
        // decode
        string decoded = UrlEncoding::decodeURIbase64(parts[1]);
        
        // delete keys: {}
        decoded.erase(0, 1);
        decoded.pop_back();
        vector<string> data = splitString(decoded, ',');
        for (auto &i : data)
        {
            vector<string> pair = splitString(i, ':');
            if (pair[0] == "\"id\"")
            {
                // remove quotes
                pair[1].erase(0, 1);
                pair[1].pop_back();
                return pair[1];
            }
        }

    }

    Session() { string(idGenerator::generateUUID()); }
    // constructo gets id_f as string and needs to be converted to char*
    Session(string id_f) : id(id_f) {}
    Session(char *id_f) : id(string(id_f)) {}
    Session(string id_f, unordered_map<string, string> values_f) : id(id_f), values(values_f) {}
};
