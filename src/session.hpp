#pragma once

#include "tools/idGenerator.hpp"
#include <string.h>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <optional>

namespace Sessions
{

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
        std::string id;
        std::unordered_map<std::string, std::string> values;

    public:
        bool create;
        bool deleted = false;
        bool isEmpty() { return id == ""; }
        void addValue(std::string key, std::string value) { values.insert(make_pair(key, value)); }
        void modifyValue(std::string key, std::string value) { values[key] = value; }
        void removeValue(std::string key) { values.erase(key); }

        std::string getId() { return id; }

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
        std::string &operator[](std::string key)
        {
            return values[key];
        }
        // convert to std::string as json
        std::string toString()
        {
            std::string result = "{";
            result += "\"id\":\"" + std::string(id) + "\",";
            for (auto &i : values)
                result += "\"" + i.first + "\":\"" + i.second + "\",";
            result.pop_back();
            result += "}";
            return result;
        }

        static std::string IDfromJWT(const std::string &jwt)
        {
            std::vector<std::string> parts = splitString(jwt, '.');
            if (parts.size() != 3)
                return "";

            if (parts[1].size() % 4 != 0)
                parts[1].append(4 - parts[1].size() % 4, '=');

            std::string decoded = UrlEncoding::decodeURIbase64(parts[1]);
            if (decoded.empty())
                return "";

            try
            {
                auto jsonPayload = nlohmann::json::parse(decoded);
                if (jsonPayload.contains("id"))
                    return jsonPayload["id"].get<std::string>();
            }
            catch (const nlohmann::json::exception &e)
            {
                // Handle JSON parsing errors
                return "";
            }

            return "";
        }

        Session() { createSession(); }
        // constructo gets id_f as std::string and needs to be converted to char*
        Session(std::string id_f) : id(id_f) {}
        Session(char *id_f) : id(std::string(id_f)) {}
        Session(std::string id_f, std::unordered_map<std::string, std::string> values_f) : id(id_f), values(values_f) {}
    };

}


class SessionsManager
{
private:
    std::unordered_map<std::string, Sessions::Session> sessions;
    idGenerator idGeneratorJWT = idGenerator("");

public:
    SessionsManager(std::string private_key) {
        idGeneratorJWT.setPrivateKey(private_key.empty() ? uuid::generate_uuid_v4() : private_key);
        sessions = std::unordered_map<std::string, Sessions::Session>();
    }

    std::string default_session_name = "SessionID";

    Sessions::Session* getSession(std::string id)
    {
        if (sessions.find(id) == sessions.end())
        {
            return &sessions[uuid::generate_uuid_v4()];
        }
        return &sessions[id];
    }

    void updateSession(Sessions::Session session)
    {
        sessions[session.getId()] = session;
    }

    Sessions::Session* validateSessionCookie(const std::string &cookie)
    {
        std::string id = Sessions::Session::IDfromJWT(cookie);

        if (id.empty())
            return getSession(uuid::generate_uuid_v4());

        if(!idGeneratorJWT.verifyJWT(cookie))
            return nullptr;

        return getSession(id);
    }

    // operator []
    Sessions::Session &operator[](const std::string &id)
    {
        return sessions[id];
    }

    void insert(Sessions::Session session)
    {
        sessions.insert(make_pair(session.getId(), session));
    }

    void erase(std::string id)
    {
        sessions.erase(id);
    }

    Sessions::Session* generateNewSession()
    {
        std::string new_id = uuid::generate_uuid_v4();
        Sessions::Session new_session(new_id); 
        sessions[new_id] = new_session;
        return &sessions[new_id];

    }

    // generate jwt from session if
    std::string generateJWT(const std::string &session_id)
    {
        return idGeneratorJWT.generateJWT(sessions[session_id].toString());
    }
};