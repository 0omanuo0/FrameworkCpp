#ifndef JINJATEMPLATING_TYPES_H
#define JINJATEMPLATING_TYPES_H

#include <iostream>
#include <vector>
#include <string>
#include <regex>
#include <sstream>
#include <fstream>
#include <map>
#include <filesystem>

#include <stdexcept>
#include <execinfo.h>
#include <dlfcn.h>
#include <cxxabi.h>
#include "json.hpp"

enum class BlockType
{
    FOR,
    IF,
    ELSE,
    INCLUDE,
    ROOT,
    SUBBLOCK
};

enum class SubBlockType
{
    ELSE,
    ELIF
};

enum class ErrorIndex
{
    EXPRESSION,
    BLOCK,
    SUBBLOCK,
    CONTENT,
    CHILDREN,
    NONE = -1
};

struct SubBlock;

struct Block
{
    BlockType type = BlockType::ROOT;
    std::string expression = "";
    int indexToPlace = -1; // index to place the block in the parent content
    std::vector<std::string> content = {};
    std::vector<SubBlock> subBlocks = {};
    std::vector<Block> children = {};
};

struct SubBlock
{
    SubBlockType type = SubBlockType::ELSE;
    std::string expression = "";
    std::vector<std::string> content = {};
    std::vector<Block> children = {};
};

struct CachedFile
{
    std::string path;
    Block content;
    std::filesystem::file_time_type timestamp;
};





struct Trace
{
    void *addr;
    std::string func;
    std::string file;
    int line;
};



typedef std::vector<Trace> StackTrace;

inline StackTrace get_stacktrace(int skip = 1)
{
    const int max_frames = 128;
    void *addrlist[max_frames + 1];

    // Obtener la lista de direcciones del stack
    int addrlen = backtrace(addrlist, sizeof(addrlist) / sizeof(void *));

    if (addrlen == 0)
    {
        std::cerr << "No stack trace available.\n";
        return {};
    }

    // Convertir las direcciones en strings
    char **symbollist = backtrace_symbols(addrlist, addrlen);

    StackTrace traces;

    // Omitimos las primeras 'skip' direcciones del stack trace
    for (int i = skip; i < addrlen; i++)
    {
        Dl_info info;
        if (dladdr(addrlist[i], &info) && info.dli_sname)
        {
            // Desmanglar el nombre de la función
            char *demangled = nullptr;
            int status = -1;
            if (info.dli_sname)
            {
                demangled = abi::__cxa_demangle(info.dli_sname, nullptr, 0, &status);
            }

            // Guardar la información del stack trace
            Trace trace;
            trace.addr = addrlist[i];
            trace.func = status == 0 ? demangled : info.dli_sname;
            trace.file = info.dli_fname;
            trace.line = info.dli_saddr ? (int)((char *)addrlist[i] - (char *)info.dli_saddr) : 0;
            traces.push_back(trace);

            free(demangled);
        }
        else
        {
            Trace trace;
            trace.addr = addrlist[i];
            trace.func = "?";
            trace.file = "?";
            trace.line = 0;
            traces.push_back(trace);
        }
    }

    free(symbollist);

    return traces;
}




// create new errors
class TemplatingError : public std::exception
{
private:
    std::string message_;
    nlohmann::json json_data_;

public:
    TemplatingError(std::string msg) : message_(msg) {}
    TemplatingError(std::string msg, nlohmann::json json_data) : message_(msg), json_data_(json_data) {}
    const char *what() const throw()
    {
        return message_.c_str();
    }
    nlohmann::json getData() const { return json_data_; }
};

// create new errors from TemplatingError, Templating_ParserError and Templating_RenderError
class Templating_ParserError : public TemplatingError
{
private:
    Block blockTrace_;

public:
    Templating_ParserError(std::string msg, Block blockTrace, nlohmann::json json_data={}) : TemplatingError(msg, json_data), blockTrace_(blockTrace) {}
    const Block getStackTrace() const { return blockTrace_; }
};

class Templating_RenderError : public TemplatingError
{
private:
    Block blockTrace_;
    StackTrace stack_trace_;
    const char *file_;
    int line_;

public:
    Templating_RenderError(std::string msg, Block blockTrace, const char *file, int line, nlohmann::json json_data={})
        : Templating_RenderError(msg, blockTrace, get_stacktrace(2), file, line, json_data) {}


    Templating_RenderError(const std::string &msg, Block blockTrace, const StackTrace& stacktrace, const char* file, int line, nlohmann::json json_data={})
        : TemplatingError(msg, json_data),
          blockTrace_(blockTrace),
          stack_trace_(stacktrace), 
          file_(file), line_(line) {}

    std::string getFile() const { return std::string(file_); }
    int getLine() const { return line_; }

    const StackTrace& getStackTrace() const { return stack_trace_; }

};

#endif // JINJATEMPLATING_TYPES_H