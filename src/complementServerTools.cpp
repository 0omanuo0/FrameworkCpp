#include "server.h"
#include "httpProto.h"

#ifndef SERVER_VALUES
    #define SERVER_VALUES

    #define BUFFER_SIZE 1024
    #define SERVER_VERSION "Soria/0.0.2b (Unix)" // Corrected
    const string REDIRECT = "VOID*REDIRECT"; // Corrected

#endif


// std::string Redirect(int socket, std::string url, std::vector<std::string> cookie){///////////areglas cookie
//     httpProtoResponse response;

//     if(cookie.empty())
//         HttpServer::sendResponse(socket, response.defaultRedirect(url));
//     else
//         HttpServer::sendResponse(socket, response.defaultRedirect_cookie(url, cookie.data()));
    
//     return REDIRECT;
// }
Response HttpServer::Redirect(std::string url){
    return Response("Redirecting to " + url, 302, {{"Location", url}});;
}

Response HttpServer::NotFound(){
    return Response(this->__not_found, 404);
}

Response HttpServer::Unauthorized(){
    return Response(this->__unauthorized, 401);
}

Response HttpServer::InternalServerError(){
    return Response(this->__internal_server_error, 500);
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
        if (sessions[i].getId() == id)
            return i; // Devuelve la posición en el vector
    
    return -1; // Retorna -1 si no se encuentra la sesión
}

Session HttpServer::__get_session(int index){
    if (index >= 0 && index < (int)sessions.size())
        return sessions[index]; // Devuelve la sesión correspondiente al índice
    else{
        auto id = string(idGenerator::generateUUID());
        return Session(id); // Devuelve una sesión vacía si el número está fuera de rango
    }
        
}

Session HttpServer::setNewSession(Session session){
    sessions.push_back(session);
    return session;
}
