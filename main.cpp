#include "src/server.hpp"



int main()
{
    std::string ssl_context[2] = {"server-cert.pem", "server-key.pem"};
    HttpServer server("10.1.1.105", 4242, ssl_context);

    server.addRoute("/test", {"GET"}, [](Request &req) {
        std::string content = "eyeyeyey";
        for (int i = 0; i < 10000; i++)
        {
            content += "eyeyeyey";
        }
        return content;
    });

    server.run();
    return 0;
}
