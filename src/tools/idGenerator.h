#ifndef IDGENERATOR_H
#define IDGENERATOR_H



#include <stdexcept>
#include <filesystem>
#include <stdexcept>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <string>
#include <random>
#include <ctime>
#include <sstream>
#include "url_encoding.h"
#include "base64.h"
#include <iostream>

namespace uuid
{
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static std::uniform_int_distribution<> dis2(8, 11);

    inline std::string generate_uuid_v4()
    {
        std::stringstream ss;
        int i;
        ss << std::hex;
        for (i = 0; i < 8; i++)
            ss << dis(gen);

        ss << "-";
        for (i = 0; i < 4; i++)
            ss << dis(gen);

        ss << "-4";
        for (i = 0; i < 3; i++)
            ss << dis(gen);

        ss << "-";
        ss << dis2(gen);
        for (i = 0; i < 3; i++)
            ss << dis(gen);

        ss << "-";
        for (i = 0; i < 12; i++)
            ss << dis(gen);
        return ss.str();
    }
}

namespace crypto_lib
{
    inline static std::string calculateSHA512(const std::string &input)
    {
        EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len;

        OpenSSL_add_all_digests();

        md = EVP_get_digestbyname("SHA512");

        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, input.c_str(), input.length());
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        EVP_MD_CTX_free(mdctx);

        std::string result;
        for (unsigned int i = 0; i < md_len; i++)
        {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", md_value[i]);
            result += hex;
        }

        return result;
    }
    inline static std::string calculateSHA512(const int &input) { return calculateSHA512(std::to_string(input)); };
};

class idGenerator
{
    private:
        std::string private_key;
    public:
        void setPrivateKey(const std::string &private_key) { this->private_key = private_key; }
        idGenerator(const std::string &private_key) : private_key(private_key) {}
        static std::string generateIDstr()
        {
            char id[32];
            for (size_t i = 0; i < 32; i++)
                id[i] = static_cast<char>(std::rand() % 10) + '0';
            return std::string(id, 32);
        }

        static std::string generateUUID() { return uuid::generate_uuid_v4(); }

        // jwt token
        std::string generateJWT(const std::string &data) {
            const std::string header = R"({"alg":"HS512","typ":"JWT"})";
            const std::string payload = data;

            std::string header_encoded = UrlEncoding::encodeURIbase64(header);
            std::string payload_encoded = UrlEncoding::encodeURIbase64(payload);

            std::string signature = crypto_lib::calculateSHA512(
                header_encoded + "." + payload_encoded + this->private_key
            );

            std::string signature_encoded = UrlEncoding::encodeURIbase64(signature);

            return header_encoded + "." + payload_encoded + "." + signature_encoded;
        }

        bool verifyJWT(const std::string &token) {
            std::string header, payload, signature;
            std::istringstream token_stream(token);
            std::getline(token_stream, header, '.');
            std::getline(token_stream, payload, '.');
            std::getline(token_stream, signature, '.');

            std::string signature_verify = crypto_lib::calculateSHA512(
                header + "." + payload + this->private_key
            );

            std::string signature_verify_encoded = UrlEncoding::encodeURIbase64(signature_verify);

            return signature == signature_verify_encoded;
        }
};

#endif