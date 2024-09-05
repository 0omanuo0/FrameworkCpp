#include <curl/curl.h>
#include <string>
#include <vector>
#include <iostream>

class CurlHandler
{
public:
    CurlHandler()
    {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    ~CurlHandler()
    {
        curl_global_cleanup();
    }

    std::string get(const std::string &url, const std::vector<std::string> &headers)
    {
        return performRequest(url, headers, "GET", "");
    }

    std::string post(const std::string &url, const std::vector<std::string> &headers, const std::string &data)
    {
        return performRequest(url, headers, "POST", data);
    }

private:
    static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
    {
        ((std::string *)userp)->append((char *)contents, size * nmemb);
        return size * nmemb;
    }

    std::string performRequest(const std::string &url, const std::vector<std::string> &headers, const std::string &method, const std::string &data)
    {
        std::string readBuffer;
        CURL *curl = curl_easy_init();

        if (curl)
        {
            struct curl_slist *chunk = nullptr;

            // Añadir headers si los hay
            for (const auto &header : headers)
            {
                chunk = curl_slist_append(chunk, header.c_str());
            }

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

            // Establecer headers si los hay
            if (chunk)
            {
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
            }

            // Configurar para POST si es necesario
            if (method == "POST")
            {
                curl_easy_setopt(curl, CURLOPT_POST, 1L);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
            }

            // Establecer tiempos de espera para evitar bloqueos
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);       // Tiempo máximo de espera de 10 segundos
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L); // Tiempo máximo de conexión de 5 segundos

            // Ejecutar la solicitud
            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK)
            {
                std::cerr << "curl_easy_perform() falló: " << curl_easy_strerror(res) << std::endl;
            }

            // Liberar la lista de headers si fue utilizada
            if (chunk)
            {
                curl_slist_free_all(chunk);
            }

            // Resetear CURL para evitar estado compartido entre solicitudes
            curl_easy_cleanup(curl);
        }
        else
        {
            std::cerr << "curl_easy_init() falló: No se pudo inicializar CURL." << std::endl;
        }

        return readBuffer;
    }
};
