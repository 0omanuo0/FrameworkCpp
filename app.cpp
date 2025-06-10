#include <iostream>
#include "src/server.hpp"
#include "db.hpp"
#include "src/curl.h"
#include <ctime>

using json = nlohmann::json;
using namespace std;



CurlHandler curl;

HttpServer server("0.0.0.0", 8444, HTTPScontext);
SoriaDB db("secrets/users.db");

vector<json> getPosts()
{
    vector<unordered_map<string, string>> db_posts = db.fetchall("SELECT * FROM POSTS ORDER BY ID DESC");
    vector<json> POSTS;
    for (const auto &post : db_posts)
    {
        json p = {{"user", post.at("autor")}, {"post", post.at("contenido")}};
        POSTS.push_back(p);
    }
    return POSTS;
}

server_types::HttpResponse showApiData(Request &req)
{
    auto data = curl.get("https://api.open-meteo.com/v1/forecast?latitude=52.52&longitude=13.41&hourly=temperature_2m", {"Content-Type: application/json"});
    nlohmann::json json_data = nlohmann::json::parse(data);

    // get the:
    // "hourly": {
    //     "temperature_2m": [ ... ],
    //     "time": [ ... ]
    // }
    // and create a dictionary with the time and temperature
    nlohmann::json hourly = json_data["hourly"];
    nlohmann::json temperature_2m = hourly["temperature_2m"];
    nlohmann::json time = hourly["time"];

    json temps;

    for (int i = 0; i < time.size(); i++)
    {
        temps.push_back({time[i], temperature_2m[i]});
    }

    return server.Render("templates/api_data.html", {{"data", temps}});
}

server_types::HttpResponse apiHome(Request &req)
{
    std::string url = "https://api.open-meteo.com/v1/forecast?latitude=52.52&longitude=13.41&hourly=temperature_2m";
    std::vector<std::string> headers = {
        "Content-Type: application/json"};

    std::string response = curl.get(url, headers);

    nlohmann::json json_response = nlohmann::json::parse(response);
    std::string res = json_response.dump(4);

    return Response(res, 200, {{"Content-Type", "application/json"}});
}

server_types::HttpResponse home(Request &req)
{
    if (req.method == POST)
    {
        if (req.session["logged"] == "true")
        {
            db.exec("INSERT INTO POSTS (autor, contenido, FECHA) VALUES (?, ?, ?)", {req.session["user"], req.form["post"], to_string(time(0))});
            vector<json> POSTS = getPosts();
            try
            {
                for (int i = 1; i <= POSTS.size(); i++)
                {
                    auto post1 = db.fetchone("SELECT * FROM POSTS WHERE ID = ?", {to_string(i)});
                    // {post1["autor"]}, post1["contenido"]
                    json p = {{"user", post1["autor"]}, {"post", post1["contenido"]}};
                    POSTS.push_back(p);
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << e.what() << '\n';
            }
            return server.Render("templates/home_logged.html", {{"user", req.session["user"]}, {"posts", POSTS}});
        }
        else
            return server.Render("templates/home.html");
        return server.Redirect("/");
    }
    else if (req.method == GET)
    {
        if (req.session["logged"] == "true")
        {
            vector<json> POSTS = getPosts();
            try
            {
                for (size_t i = 1; i <= POSTS.size(); i++)
                {
                    auto post1 = POSTS[i];
                    json p = {{"user", post1["autor"]}, {"post", post1["contenido"]}};
                    POSTS.push_back(p);
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << e.what() << '\n';
            }
            json data = {{"user", req.session["user"]}, {"posts", POSTS}};
            // std::cout << data.dump(4) << std::endl;
            return server.Render("templates/home_logged.html", data);
        }
        else
            return server.Render("templates/home.html");
    }
    return server.NotFound();
}

server_types::HttpResponse user_account(Request &req)
{
    auto u_idt = req.parameters.get<std::string>("iuserid");
    if (req.session["logged"] == "true" && u_idt == req.session["user"]){
        auto user = db.fetchone("SELECT * FROM USERS WHERE ID = ?", {u_idt});
        return server.Render("templates/user.html", {{"user", u_idt}, {"pass", user["pass"]}});
    }
    else
        return server.Redirect("/login");
}

server_types::HttpResponse images(Request &req)
{
    auto u_idt = req.parameters.getString("iuserid");
    return server.Render("templates/image.html", {{"id", u_idt}});
}

server_types::HttpResponse login(Request &req)
{
    if (req.method == GET)
    {
        if (req.session["logged"] == "true")
            return server.Redirect("/");
        return server.Render("templates/login.html");
    }
    else if (req.method == POST)
    {
        // vector<vector<string>> USERS;
        try
        {
            auto user = db.fetchone("SELECT * FROM USERS WHERE ID = ?", {req.form["fname"]});

            if (user.size() == 0)
                return server.Render("templates/login.html", {{"error", "true"}});

            if (crypto_lib::calculateSHA512(req.form["fpass"]) == user["pass"] && req.form["fname"] == user["user"])
            {
                req.session["logged"] = "true";
                req.session["user"] = user["user"];
                return server.Redirect("/");
            }
            return server.Render("templates/login.html", {{"error", "true"}});
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
            server.InternalServerError();
        }
    }
    return server.NotFound();
}

server_types::HttpResponse logout(Request &req)
{
    if (req.session["logged"] == "true")
        req.session.destroySession();
    return server.Redirect("/login");
}

server_types::HttpResponse portfolio(Request &req)
{
    // get data from static/content/proj.json
    std::ifstream file("static/content/proj.json");
    if (!file.is_open())
        return server.NotFound();
    std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    nlohmann::json json_data = nlohmann::json::parse(data);
    return server.Render(std::string("templates/portfolio.html"), json_data);
}

int main(int argc, char **argv)
{
    server.addRoute("/api", {GET, POST}, apiHome);
    server.addRoute("/api/<id:int>", {GET, POST}, apiHome);

    server.addRoute("/show", {GET, POST}, showApiData);

    // Ruta sin variables
    server.addRoute("/home", {GET, POST}, home);
    server.addRoute("/", {GET, POST}, home);
    server.addRoute("/user/<iuserid>", {GET, POST}, user_account);

    server.addRoute("/login", {GET, POST}, login);
    server.addRoute("/logout", {GET}, logout);
    server.addRoute("/image/<id>", {GET}, images);

    server.addRoute("/portfolio", {GET}, portfolio);

    server.run();
}
