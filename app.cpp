#include <iostream>
#include "src/server.h"
#include "src/usersdb.h"
#include "src/curl.h"



using json = nlohmann::json;
using namespace std;

const int PORT = 8444;

CurlHandler curl;

string HTTPScontext[] = {"secrets/cert.pem", "secrets/key.pem"};

HttpServer server(PORT, HTTPScontext, "ubuntu-manu.local");
UsersDB DATABASE("secrets/users.db");

types::HttpResponse showApiData(Request &req)
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

types::HttpResponse apiHome(Request &req)
{
    std::string url = "https://api.open-meteo.com/v1/forecast?latitude=52.52&longitude=13.41&hourly=temperature_2m";
    std::vector<std::string> headers = {
        "Content-Type: application/json"
    };

    std::string response = curl.get(url, headers);

    nlohmann::json json_response = nlohmann::json::parse(response);
    std::string res = json_response.dump(4);

    return Response(res, 200, {{"Content-Type", "application/json"}});
}

types::HttpResponse home(Request &req)
{
    if (req.method == POST)
    {
        if (req.session["logged"] == "true")
        {
            DATABASE["POSTS"].insertRow({{"autor", req.session["user"]}, {"contenido", req.form["post"]}});
            vector<json> POSTS;
            try
            {
                for (int i = 1; i <= DATABASE["POSTS"].countRows(); i++)
                {
                    unordered_map post1 = DATABASE["POSTS"].getByID(to_string(i));
                    // {post1["autor"]}, post1["contenido"]
                    json p = { {"user", post1["autor"]}, {"post", post1["contenido"]} };
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
            vector<json> POSTS;
            try
            {
                for (size_t i = 1; i <= DATABASE["POSTS"].countRows(); i++)
                {
                    unordered_map post1 = DATABASE["POSTS"].getByID(to_string(i));
                    json p = { {"user", post1["autor"]}, {"post", post1["contenido"]} };
                    POSTS.push_back(p);
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << e.what() << '\n';
            }
            json data = {{"user", req.session["user"]}, {"posts", POSTS}};
            std::cout << data.dump(4) << std::endl;
            return server.Render("templates/home_logged.html", data);
        }
        else
            return server.Render("templates/home.html");
    }
}

types::HttpResponse user_account(Request &req)
{
    if (req.session["logged"] == "true" && req.parameters["iuserid"] == req.session["user"])
        return server.Render("templates/user.html", {{"user", req.parameters["iuserid"]}, {"pass", DATABASE.getUser(req.parameters["iuserid"])[2]}});
    else
        return server.Redirect("/login");
}

types::HttpResponse images(Request &req)
{
    return server.Render("templates/image.html", {{"id", req.parameters["iuserid"]}});
}

types::HttpResponse login(Request &req)
{
    if (req.method == GET)
    {
        if (req.session["logged"] == "true" )
            return server.Redirect("/");
        return server.Render("templates/login.html");
    }
    else if (req.method == POST)
    {
        // vector<vector<string>> USERS;
        try
        {
            vector<string> user = DATABASE.getUser(req.form["fname"]);

            if(user.size() == 0)
                return server.Render("templates/login.html", {{"error", "true"}});

            if (crypto_lib::calculateSHA512(req.form["fpass"]) == user[2] && req.form["fname"] == user[1])
            {
                req.session["logged"] = "true";
                req.session["user"] = user[1];
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

types::HttpResponse logout(Request &req)
{
    if (req.session["logged"] == "true" )
        req.session.destroySession();
    return server.Redirect("/login");
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

    server["secret_key"] = uuid::generate_uuid_v4();
    server["max_connections"] = 10;

    server.addRoute("/api", apiHome, {GET, POST});
    server.addRoute("/api/<id>", apiHome, {GET, POST});

    server.addRoute("/show", showApiData, {GET, POST});

    // Ruta sin variables
    server.addRoute("/home", home, {GET, POST});
    server.addRoute("/", home, {GET, POST});
    server.addRoute("/user/<iuserid>", user_account, {GET, POST});

    server.addRoute("/login", login, {GET, POST});
    server.addRoute("/logout", logout, {GET});
    server.addRoute("/image/<id>", images, {GET});

    server.startListener();
}
