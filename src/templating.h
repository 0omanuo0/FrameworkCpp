#ifndef TEMPLATING_H
#define TEMPLATING_H

// #include "server.h"

#include <iostream>
#include <cstring>
#include <vector>
#include <fstream>
#include <filesystem>
#include <map>
#include <regex>
#include <string>

#include "idGenerator.h"
#include "tinyexpr.h"
#include "server.h"
#include "json.hpp"
// #include "server.h"

class HttpServer;
using json = nlohmann::json;
using namespace std;

class Templating
{
private:
    string __find_expressions(string line, const map<string, string> &data);

    string __find_statements(string line, ifstream &file, const map<string, string> &data);
    string __render_statements(string find, const map<string, string> &data);
    string __render_block(const string &path, const map<string, string> &data);
    string __render_for(string find, ifstream &file, const map<string, string> &data);
    string __render_if(string find, ifstream &file, const map<string, string> &data);


    // string __pre_cache_expressions(string line, templating_cache &templatate_cache);
    // string __pre_cache_statements( string line, templating_cache &templatate_cache, ifstream &file);
    // string __pre_cache_for(        string find, templating_cache &templatate_cache, ifstream &file);

    // templating_cache cached_files(string path);

    double __evaluate_expression(string expression, const map<string, string> &data);

    const regex if_pattern = regex(R"(\bif\s+([^{}]+)\s*)");
    const regex else_pattern = regex(R"(\{\%\s+else\s+\%\})");
    const regex endif_pattern = regex(R"(\{\%\s+endif\s+\%\})");

    const regex for_pattern = regex(R"(\bfor\s+([^{}]+)\s+in\s+([^{ }]+)\s*)");
    const regex endfor_pattern = regex(R"(\{\%\s+endfor\s+\%\})");

    const regex block_pattern = regex(R"(\{%\s+block\s+content\s+%\})");
    const regex endblock_pattern = regex(R"(\{%\s+endblock\s+content\s+%\})");

    const regex patron_include = regex(R"(\binclude\s+"([^"]*)\s*)");
    const regex patron_urlfor = regex(R"(\burlfor\(\s*([^\(\)]+)\s*\))");

    const regex statement_pattern = regex(R"(\{\%\s*([^{}]+)\s*\%\})");
    const regex expression_pattern = regex(R"(\{\{\s*([^{}]+)\s*\}\})");



public:
    HttpServer *server;
    Templating(){};

    string Render(const string &route, const map<string, string> &data);
};

vector<string> FindArray(const string &content);

#endif // TEMPLATING_H
