#include <curl/curl.h>
#include <string>
#include <vector>


class CurlHandler {
public:
    CurlHandler() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl = curl_easy_init();
    }

    ~CurlHandler() {
        if (curl) {
            curl_easy_cleanup(curl);
        }
        curl_global_cleanup();
    }

    std::string get(const std::string& url, const std::vector<std::string>& headers) {
        return performRequest(url, headers, "GET", "");
    }

    std::string post(const std::string& url, const std::vector<std::string>& headers, const std::string& data) {
        return performRequest(url, headers, "POST", data);
    }

private:
    CURL* curl;

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    std::string performRequest(const std::string& url, const std::vector<std::string>& headers, const std::string& method, const std::string& data) {
        std::string readBuffer;

        if (curl) {
            struct curl_slist* chunk = nullptr;
            for (const auto& header : headers) {
                chunk = curl_slist_append(chunk, header.c_str());
            }

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

            if (chunk) {
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
            }

            if (method == "POST") {
                curl_easy_setopt(curl, CURLOPT_POST, 1L);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
            }

            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            }

            if (chunk) {
                curl_slist_free_all(chunk);
            }
        }

        return readBuffer;
    }
};