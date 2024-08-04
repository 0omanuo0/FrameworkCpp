

#include "gtest/gtest.h"
#include "httpMethods.h"

const std::string headerExample = "POST /login HTTP/1.1\r\nHost: 10.1.1.101:8444\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0\r\nAccept: text/html,application/xhtml xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg xml,*/*;q=0.8\r\nAccept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 29\r\nOrigin: https://10.1.1.101:8444\r\nDNT: 1\r\nConnection: keep-alive\r\nReferer: https://10.1.1.101:8444/login\r\nCookie: SessionID=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjZiYjc5NjZkLTE3NTgtNDhmOC05ZmVjLWRhMzRmM2I2OGQyYyIsImxvZ2dlZCI6IiJ9.ZjcwYzkwMzE3ZGNjMjcwYjBjM2ViMzBhNTE2MWVmOGI4ZmQ5NWVmYmZhOGRiNWIyMWZiN2JmMjBiZmEzYTlhNmY1MDM5NTQxY2FkMDlmZTRmMWIyMGYyYmIyMDBlYjkxZWE5MjI2ZGM3NGY3MTg4YzIyNzFjYjQxMDI0ZmZkNzY\r\nUpgrade-Insecure-Requests: 1\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-User: ?1\r\nSec-GPC: 1\r\nPriority: u=0, i\r\n\r\nfname=as da sd&fpass=a sda sd";

TEST(HttpMethodsTest, parseHeaders)
{
    httpHeaders headers;

    headers.loadParams(headerExample);

    ASSERT_EQ(headers.getMethod(), "POST");
    ASSERT_EQ(headers.getRoute(), "/login");
    ASSERT_EQ(headers.getQuery(), "");
    ASSERT_EQ(headers["Host"].get<std::string>(), "10.1.1.101:8444");

    ASSERT_EQ(headers["User-Agent"].get<std::string>(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0");
    ASSERT_EQ(headers.getRequest().content.getDict()["fname"], "as da sd");

}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}