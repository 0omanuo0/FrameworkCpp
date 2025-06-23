#include <curl/curl.h>
#include <string>
#include <vector>

enum class HttpError
{
    NONE = 0,
    TIMEOUT,
    CONNECTION_FAILED,
    SSL_ERROR,
    UNKNOWN_ERROR
};

typedef struct
{
    HttpError error = HttpError::NONE;
    int status_code;
    std::string url;
    std::vector<std::string> headers;
    std::string body;
} HttpResponse;

class CurlHandler
{
public:
    CurlHandler()
    {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl = curl_easy_init();
    }

    ~CurlHandler()
    {
        if (curl)
        {
            curl_easy_cleanup(curl);
        }
        curl_global_cleanup();
    }

    HttpResponse get(const std::string &url, const std::vector<std::string> &headers, bool insecure = false)
    {
        return performRequest(url, headers, "GET", "", insecure);
    }

    HttpResponse post(const std::string &url, const std::vector<std::string> &headers, const std::string &data)
    {
        return performRequest(url, headers, "POST", data);
    }

private:
    CURL *curl;

    static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
    {
        ((std::string *)userp)->append((char *)contents, size * nmemb);
        return size * nmemb;
    }

    HttpResponse performRequest(const std::string &url, const std::vector<std::string> &headers, const std::string &method, const std::string &data, bool insecure = false)
    {
        HttpResponse response;
        response.url = url;
        response.status_code = 0;
        response.body.clear();
        response.headers.clear();
        response.error = HttpError::NONE;

        std::string readBuffer;
        std::string headerBuffer;

        if (curl)
        {
            struct curl_slist *chunk = nullptr;
            for (const auto &header : headers)
            {
                chunk = curl_slist_append(chunk, header.c_str());
            }

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

            // Capture headers
            curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headerBuffer);

            // Set timeout to 1 second
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L);

            if (chunk)
            {
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
            }

            if (method == "POST")
            {
                curl_easy_setopt(curl, CURLOPT_POST, 1L);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
            }

            if (insecure)
            {
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            }
            else
            {
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
            }

            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK)
            {
                // fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                switch (res)
                {
                case CURLE_OPERATION_TIMEDOUT:
                    response.error = HttpError::TIMEOUT;
                    break;
                case CURLE_COULDNT_CONNECT:
                    response.error = HttpError::CONNECTION_FAILED;
                    break;
                case CURLE_SSL_CONNECT_ERROR:
                case CURLE_PEER_FAILED_VERIFICATION:
                    // case CURLE_SSL_CACERT:
                    response.error = HttpError::SSL_ERROR;
                    break;
                default:
                    response.error = HttpError::UNKNOWN_ERROR;
                    break;
                }
            }
            else
            {
                long http_code = 0;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                response.status_code = static_cast<int>(http_code);

                // Parse headers
                size_t start = 0, end;
                while ((end = headerBuffer.find("\r\n", start)) != std::string::npos)
                {
                    std::string headerLine = headerBuffer.substr(start, end - start);
                    if (!headerLine.empty())
                        response.headers.push_back(headerLine);
                    start = end + 2;
                }
            }

            if (chunk)
            {
                curl_slist_free_all(chunk);
            }
        }
        else
        {
            response.error = HttpError::CONNECTION_FAILED;
        }

        response.body = readBuffer;
        return response;
    }
};