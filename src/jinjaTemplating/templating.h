#ifndef TEMPLATING_H
#define TEMPLATING_H

#include <iostream>
#include <vector>
#include <string>
#include <regex>
#include <sstream>
#include <fstream>
#include <map>
#include <ctime>
#include <chrono>
#include <filesystem>
#include <set>

#include "types.h"
#include "json.hpp"
#include "tools.h"
#include "tinyexpr.h"
#include "../server.h"

class HttpServer;

class Templating
{
private:
    const std::regex statement_pattern = std::regex(R"(\{\%\s+([^{}]+)\s+\%\})");
    const std::regex expression_pattern = std::regex(R"(\{\{\s*([^{}]+)\s*\}\})");

    const std::regex if_pattern = std::regex(R"(\bif\s+([^{}]+)\s*)");
    const std::regex elif_pattern = std::regex(R"(\belif\s+([^{}]+)\s*)");
    const std::regex else_pattern = std::regex(R"(\belse\s*)");
    const std::regex endif_pattern = std::regex(R"(\s*endif\s*)");

    const std::regex for_pattern = std::regex(R"(\bfor\s+([^{}]+)\s*)");
    const std::regex endfor_pattern = std::regex(R"(\s*endfor\s*)");

    const std::regex include_pattern = std::regex(R"(\binclude\s+"([^"]*)\s*)");

    const std::regex urlfor_string_pattern = std::regex(R"(\burlfor\(\s*(['"])([^{}]+)\1\s*\))");
    const std::regex urlfor_pattern = std::regex(R"(\burlfor\(\s*([^{}]+)\s*\))");

    Block BlockParser(std::istream &stream, Block parent = Block());
    CachedFile generateCache(std::string path);

    std::string __Render(Block block, nlohmann::json &data);
    std::string __renderIfBlock(Block& ifBlock, nlohmann::json &data);
    std::string __renderForBlock(Block& forBlock, nlohmann::json &data);
    std::string __renderExpressions(std::string expression, nlohmann::json &data);

    std::vector<int> findChildren(Block block, int lineN);

    std::map<std::string, CachedFile> cachedTemplating;
    bool storeCache;

    
public:

    HttpServer *server;

    Templating(bool storeCache = false);
    std::string Render(const std::string &file, const nlohmann::json &data);
    std::string Render(const std::string &file, const std::map<std::string, std::string> &data);
    std::string Render(const std::string &file);
    std::string Render(const std::string &file, const std::string &data);
    
};



#endif