#include <iostream>
#include "src/server.h"
#include "users.hpp"
#include "src/usersdb.h"
#include "src/idGenerator.h"


using namespace std;

const int PORT = 8444;
const int MAX_CONNECTIONS = 500;

string HTTPScontext[] = {"secrets/cert.pem", "secrets/key.pem"};

HttpServer server(PORT, HTTPScontext, uuid::generate_uuid_v4().c_str(), "ubuntu-manu.local", MAX_CONNECTIONS);
UsersDB DATABASE("secrets/users.db");

string home(Args &args)
{
    if (args.request.method == POST)
    {
        if (args.session["logged"] == "true")
        {
            DATABASE["POSTS"].insertRow({{"autor", args.session["user"]}, {"contenido", args.request.content["post"]}});
            vector<post> POSTS;
            try
            {
                for (size_t i = 1; i <= DATABASE["POSTS"].countRows(); i++)
                {
                    unordered_map post1 = DATABASE["POSTS"].getByID(to_string(i));
                    post p = {{post1["autor"]}, post1["contenido"]};
                    POSTS.push_back(p);
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << e.what() << '\n';
            }

            return server.Render("templates/home_logged.html", {{"user", args.session["user"]}, {"posts", posts_to_string(POSTS)}});
        }
        else
            return server.Render("templates/home.html");
        return Redirect("/");
    }
    else if (args.request.method == GET)
    {
        if (args.session["logged"] == "true")
        {
            vector<post> POSTS;
            try
            {
                for (size_t i = 1; i <= DATABASE["POSTS"].countRows(); i++)
                {
                    unordered_map post1 = DATABASE["POSTS"].getByID(to_string(i));
                    post p = {{post1["autor"]}, post1["contenido"]};
                    POSTS.push_back(p);
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << e.what() << '\n';
            }

            return server.Render("templates/home_logged.html", {{"user", args.session["user"]}, {"posts", posts_to_string(POSTS)}});
        }
        else
            return server.Render("templates/home.html");
    }
}

string user_account(Args &args)
{
    if (args.session["logged"] == "true" && args.vars[0] == args.session["user"])
        return server.Render("templates/user.html", {{"user", args.vars[0]}, {"pass", DATABASE.getUser(args.vars[0])[2]}});
    else
        return Redirect("/login");
}

string images(Args &args)
{
    return server.Render("templates/image.html", {{"id", args.vars[0]}});
}

string login(Args &args)
{
    if (args.request.method == GET)
    {
        if (args.session["logged"] == "true" )
            return Redirect("/");
        return server.Render("templates/login.html");
    }
    else if (args.request.method == POST)
    {
        // vector<vector<string>> USERS;
        try
        {
            vector<string> user = DATABASE.getUser(args.request.content["fname"]);

            if (crypto_lib::calculateSHA512(args.request.content["fpass"]) == user[2] && args.request.content["fname"] == user[1])
            {
                args.session["logged"] = "true";
                args.session["user"] = user[1];
                return Redirect("/");
            }
            return server.Render("templates/login.html", {{"error", "true"}});
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
        }
    }
    return "error";
}

string logout(Args &args)
{
    if (args.session["logged"] == "true" )
        args.session.destroySession();
    return Redirect("/login");
}

int main(int argc, char **argv)
{
    try
    {

        // DATABASE["POSTS"].insertRow({{"autor", "manu"}, {"contenido", "HOLA :D"}, {"FECHA", "2022-01-01"}});
        // DATABASE["POSTS"].insertRow({{"autor", "juan"}, {"contenido", "AAAAAAA"}, {"FECHA", "2022-01-01"}});
        // DATABASE["POSTS"].insertRow({{"autor", "manu"}, {"contenido", "asdf"}, {"FECHA", "2022-01-01"}});
        // DATABASE["POSTS"].insertRow({{"autor", "rich"}, {"contenido", "adios"}, {"FECHA", "2022-01-01"}});

        DATABASE.insertUser("manu", {{"pass", crypto_lib::calculateSHA512("asdf1234")}});
        DATABASE.insertUser("juan", {{"pass", crypto_lib::calculateSHA512("123")}});
        DATABASE.insertUser("rich", {{"pass", crypto_lib::calculateSHA512("456")}});
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
    }

    // Ruta sin variables
    server.addRoute("/home", home, {GET, POST});
    server.addRoute("/", home, {GET, POST});
    server.addRoute("/user/<iuserid>", user_account, {GET, POST});

    server.addRoute("/login", login, {GET, POST});
    server.addRoute("/logout", logout, {GET});
    server.addRoute("/image/<id>", images, {GET});

    server.setup();
    server.startListener();
}
