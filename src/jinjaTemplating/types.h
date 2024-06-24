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

#endif // JINJATEMPLATING_TYPES_H