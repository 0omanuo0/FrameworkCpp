#include "src/server.hpp"



int main()
{
    std::string ssl_context[2] = {"secrets/cert.pem", "secrets/key.pem"};
    HttpServer server("10.1.1.105", 4243, ssl_context);

    server.addRoute("/test", {"GET"}, [](Request &req) {
        std::string content = "eyeyeyey";
        for (int i = 0; i < 10000; i++)
        {
            content += "eyeyeyey";
        }
        return content;
    });

    server.addRoute("/main/<id>", {"GET"}, [](Request &req) {
        std::string response = R"(
        <html>
            <head>
                <title>Test</title>
            </head>
            <body>
                <h1>Test</h1>
                <p>id: )" + req.parameters["id"] + R"(</p>
            </body>
        </html>)";
        return response;
    });

    server.addRoute("/show", {"GET"}, [&server](Request &req) {
        // 1. load the file into files/forecast.json 
        std::ifstream file("templates/files/forecast.json");
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        nlohmann::json json_data = nlohmann::json::parse(content);

        nlohmann::json hourly = json_data["hourly"];
        nlohmann::json temperature_2m = hourly["temperature_2m"];
        nlohmann::json time = hourly["time"];

        nlohmann::json temps;

        for (int i = 0; i < time.size(); i++)
        {
            temps.push_back({time[i], temperature_2m[i]});
        }

        // 2. render template
        return server.Render("templates/api_data.html", {{"data", temps}});
    });

    server.run();
    return 0;
}
