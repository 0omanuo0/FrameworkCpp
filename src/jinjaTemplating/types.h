#ifndef JINJATEMPLATING_TYPES_H
#define JINJATEMPLATING_TYPES_H

#include <iostream>
#include <vector>
#include <string>
#include <regex>
#include <sstream>
#include <fstream>
#include <map>

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

    // std::string toString(std::pair<ErrorIndex, std::string> errorLine = {ErrorIndex::NONE, ""})
    // {
    //     // convert to jinja error template html
    //     const std::string hereError = "<p class='error'>Error here: <span>" + errorLine.second + "</span></p>\n";

    //     std::string result = "<li class='block'>\n";

    //     result += "<div class='block-head'>\n";
    //     result += "     <h1 class='block-type'>Block type: <span>" + std::to_string(static_cast<int>(type)) + "</span></h1>\n";
    //     result += "     <p class='block-expression'>Block expression: <span>" + expression + "</span></p>\n";
    //     if (errorLine.first == ErrorIndex::EXPRESSION)
    //         result += hereError;
    //     result += "</div>\n";

    //     result += "<div class='block-content'>\n";
    //     result += "     <h3>Block content:</h3>\n";
    //     result += "     <ol class='block-content'>\n";
    //     for (auto &line : content)
    //         result += "         <li class='block-line'>" + line + "</li>\n";
    //     if (errorLine.first == ErrorIndex::CONTENT)
    //         result += hereError;
    //     result += "     </ol>\n";
    //     result += "</div>\n";

    //     result += "<div class='block-subblocks'>\n";
    //     result += "     <h3>Block subblocks:</h3>\n";
    //     result += "     <ol class='block-subblocks'>\n";
    //     if (errorLine.first == ErrorIndex::SUBBLOCK)
    //         result += hereError;
    //     result += "     </ol>\n";
    //     result += "</div>\n";

    //     result += "<div class='block-children'>\n";
    //     result += "     <h3>Block children:</h3>\n";
    //     result += "     <ol class=''>\n";
    //     for (auto &child : children)
    //         result += child.toString();
    //     if (errorLine.first == ErrorIndex::CHILDREN)
    //         result += hereError;
    //     result += "     </ol>\n";
    //     result += "</div>\n";

    //     result += "</li>\n";

    //     return result;
    // }
};

struct SubBlock
{
    SubBlockType type = SubBlockType::ELSE;
    std::string expression = "";
    std::vector<std::string> content = {};
    std::vector<Block> children = {};

    // std::string toString()
    // {

    //     std::string result = "<li class='subblock'>\n";

    //     result += "<div class='subblock-head'>\n";
    //     result += "     <h1 class='subblock-type'>SubBlock type: <span>" + std::to_string(static_cast<int>(type)) + "</span></h1>\n";
    //     result += "     <p class='subblock-expression'>SubBlock expression: <span>" + expression + "</span></p>\n";
    //     result += "</div>\n";

    //     result += "<div class='subblock-content'>\n";
    //     result += "     <h3>SubBlock content:</h3>\n";
    //     result += "     <ol class='subblock-content'>\n";
    //     for (auto &line : content)
    //         result += "         <li class='subblock-line'>" + line + "</li>\n";
    //     result += "     </ol>\n";
    //     result += "</div>\n";

    //     result += "<div class='subblock-children'>\n";
    //     result += "     <h3>SubBlock children:</h3>\n";
    //     result += "     <ol class=''>\n";
    //     for (auto &child : children)
    //         result += child.toString();
    //     result += "     </ol>\n";
    //     result += "</div>\n";

    //     result += "</li>\n";

    //     return result;
    // }
};

struct CachedFile
{
    std::string path;
    Block content;
    std::filesystem::file_time_type timestamp;
};


// create new errors
class TemplatingError : public std::exception
{
    std::string message;
    Block stackTrace;

public:
    TemplatingError(std::string message, Block stackTrace) : message(message), stackTrace(stackTrace) {}
    const char *what() const throw()
    {
        return message.c_str();
    }
    const Block getStackTrace() const
    {
        return stackTrace;
    }
};

// create new errors from TemplatingError, Templating_ParserError and Templating_RenderError
class Templating_ParserError : public TemplatingError
{
public:
    Templating_ParserError(std::string message, Block stackTrace) : TemplatingError(message, stackTrace) {}
};

class Templating_RenderError : public TemplatingError
{
public:
    Templating_RenderError(std::string message, Block stackTrace) : TemplatingError(message, stackTrace) {}
};

#endif // JINJATEMPLATING_TYPES_H