#include <iostream>
#include "src/server.h"
#include "src/idGenerator.h"
// #include "httpProto.h"

const int PORT = 8080;
const int MAX_CONNECTIONS = 5;

HttpServer server(9443);

std::string home(Args &args)
{
    if (!args.vars.empty())
    {
        std::string admin = args.vars[0];
        std::string id = args.vars[1];
        if (admin == "1234")
            return Redirect(args.socket, "/dashboard");

        return "<h1>Hola, admin " + admin + ", tu ID es " + id + "</h1>";
    }
    else
    {
        // Ruta sin variables
        std::string sessionID = args.method.params_get.cookies["SessionID"];
        Session session = server.findMatchSession(sessionID);
        if (session.obtainValue("logged") == "true" && session.sessionUser.id != "")
            return "Bienvenido al dashboard: " +
                   session.sessionUser.id;
        return Redirect(args.socket, "/login");;
    }
}

std::string login(Args &args)
{
    if (args.method.type == GET)
    {
        std::map<std::string, std::string> content = args.method.params_post.content;
        std::string sessionID = args.method.params_get.cookies["SessionID"];
        Session session = server.findMatchSession(sessionID);
        // for (const auto &session : server.sessions)
        // {
        //     for (const auto &pair : session.sessionUser.values)
        //     {
        //         std::cout << pair.first << ": " << pair.second << std::endl;
        //     }
        // }
        if (session.obtainValue("logged") == "true" && session.sessionUser.id != "")
            return "logged in";
        return "<form action=\"/login\" method=\"post\">"
               "<label for=\"name\">Name:</label>"
               "<input type=\"text\" id=\"fname\" name=\"fname\"><br><br>"
               "<label for=\"pass\">Pass:</label>"
               "<input type=\"password\" id=\"fpass\" name=\"fpass\"><br><br>"
               "<input type=\"submit\" value=\"Submit\">"
               "</form>";
    }
    else if (args.method.type == POST)
    {
        std::string output;

        std::map<std::string, std::string> content = args.method.params_post.content;

        if (content["fpass"] == "123" && content["fname"] == "manu")
        {
            Session s1 = Session(idGenerator::generateIDstr(), "logged", "true");
            server.sessions.push_back(s1);
            return Redirect(args.socket, std::string("/dashboard"));
        }
    }
    return "error";
}

int main(int argc, char **argv)
{
    // Ruta sin variables
    server.addRoute("/dashboard", home, {GET});

    server.addRoute("/login", login, {GET, POST});

    server.addRoute("/dashboard/<admin>/<id>",
                    home, {GET},
                    std::vector<std::string>(),
                    std::string());

    server.addFilesHandler("/files/", "./files/");
    server.setup();
    server.startListener(server.serverSocket);
}