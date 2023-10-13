#include "server.h"
#include "httpProto.h"

// std::string Redirect(int socket, std::string url, std::vector<std::string> cookie){///////////areglas cookie
//     httpProtoResponse response;

//     if(cookie.empty())
//         HttpServer::sendResponse(socket, response.defaultRedirect(url));
//     else
//         HttpServer::sendResponse(socket, response.defaultRedirect_cookie(url, cookie.data()));
    
//     return REDIRECT;
// }
std::string Redirect(std::string url){///////////areglas cookie
    return REDIRECT + url;
}

bool starts_with_prefix(const std::string& url){
    std::string prefix("://");
    if (url.size() <= prefix.size())
        return false;
    int index = url.find(prefix);
    if(index != -1)
        return url.substr(index , prefix.size()) == prefix;
    else
        return false;
}

int HttpServer::__find_match_session(std::string id)
{
    for (int i = 0; i < (int)sessions.size(); i++)
        if (sessions[i].id == id)
            return i; // Devuelve la posición en el vector
    
    return -1; // Retorna -1 si no se encuentra la sesión
}

Session HttpServer::__get_session(int index){
    if (index >= 0 && index < (int)sessions.size())
        return sessions[index]; // Devuelve la sesión correspondiente al índice
    else
        return Session(); // Devuelve una sesión vacía si el número está fuera de rango
}

Session HttpServer::setNewSession(Session session){
    sessions.push_back(session);
    return session;
}
