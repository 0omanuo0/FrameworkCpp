#include "templating.h"

std::string Templating::Render(const std::string &file, const std::map<std::string, std::string> &data)
{
    nlohmann::json jsonData = data;
    return this->Render(file, jsonData);
}

std::string Templating::Render(const std::string &file, const std::string &data)
{
    nlohmann::json jsonData = nlohmann::json::parse(data);
    return this->Render(file, jsonData);
}

std::string Templating::Render(const std::string &file)
{
    nlohmann::json jsonData;
    return this->Render(file, jsonData);
}

std::string Templating::Render(const std::string &file, const nlohmann::json &data)
{
    
    nlohmann::json dataCopy = data;
    Block root;

    try
    {
        if (this->cachedTemplating.count(file) <= 0)
        {
            this->cachedTemplating[file] = generateCache(file);
            root = this->cachedTemplating[file].content;
        }
        else
        {
            auto cachedFile = this->cachedTemplating[file];
            auto lastWriteTime = std::filesystem::last_write_time(file);
            if (lastWriteTime > cachedFile.timestamp)
            {
                this->cachedTemplating[file] = generateCache(file);
            }
            root = this->cachedTemplating[file].content;
        }

        if (this->storeCache)
        {
            // store all the cachedTemplating as byte array in templating.cache
            std::ofstream cacheFile("templating.cache", std::ios::binary);
            cacheFile.write((char *)&cachedTemplating, sizeof(cachedTemplating));

            cacheFile.close();
        }

        return this->__Render(root, dataCopy);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';

        return "";
    }
}

Templating::Templating(bool storeCache)
{
    this->storeCache = storeCache;

    if (this->storeCache)
    {
        // load the cache from the file templating.cache
        std::ifstream cacheFile("templating.cache", std::ios::binary);
        if (cacheFile)
        {
            cacheFile.read((char *)&this->cachedTemplating, sizeof(this->cachedTemplating));
        }
        cacheFile.close();
    }
}

CachedFile Templating::generateCache(std::string path)
{
    std::ifstream file(path);
    if (!file)
    {
        std::cerr << "Error opening file: " << path << std::endl;
        throw std::runtime_error("Error opening file: " + path);
    }

    Block rootBlock = this->BlockParser(file);
    file.close();

    CachedFile cachedFile;
    cachedFile.path = path;
    cachedFile.content = rootBlock;
    cachedFile.timestamp = std::filesystem::last_write_time(path);

    return cachedFile;
}

std::vector<int> Templating::findChildren(Block block, int lineN)
{
    std::vector<int> indices;
    for (size_t i = 0; i < block.children.size(); i++)
    {
        if (block.children[i].indexToPlace == lineN)
        {
            indices.push_back(i);
        }
    }
    return indices;
}

std::string Templating::__Render(Block block, nlohmann::json &data)
{
    std::string result = "";
    int size = block.content.size() + block.children.size();

    for (size_t lineN = 0; lineN < size; lineN++)
    {
        std::vector<int> childrenIndices = this->findChildren(block, lineN);

        for (auto &index : childrenIndices)
        {
            Block &childBlock = block.children[index];

            switch (childBlock.type)
            {
            case BlockType::IF:
                result += this->__renderIfBlock(childBlock, data);
                break;

            case BlockType::FOR:
                result += this->__renderForBlock(childBlock, data);
                break;

            case BlockType::INCLUDE:
                result += this->__Render(childBlock, data);
                break;

            default:
                break;
            }
        }

        if (lineN < block.content.size())
        {
            result += this->__renderExpressions(block.content[lineN], data) + "\n";
        }
    }

    return result;
}

std::string Templating::__renderIfBlock(Block &ifBlock, nlohmann::json &data)
{
    std::string result = "";
    if ((bool)__evaluateExpression(ifBlock.expression, data))
    {
        result += this->__Render(ifBlock, data);
    }
    else
    {
        for (auto &subBlock : ifBlock.subBlocks)
        {
            if (subBlock.type == SubBlockType::ELIF && (bool)__evaluateExpression(subBlock.expression, data))
            {
                Block newBlock;
                newBlock.type = BlockType::SUBBLOCK;
                newBlock.content = subBlock.content;
                newBlock.children = subBlock.children;
                result += this->__Render(newBlock, data);
                break;
            }
            else if (subBlock.type == SubBlockType::ELSE)
            {
                Block newBlock;
                newBlock.type = BlockType::SUBBLOCK;
                newBlock.content = subBlock.content;
                newBlock.children = subBlock.children;
                result += this->__Render(newBlock, data);
                break;
            }
        }
    }
    return result;
}

std::string Templating::__renderForBlock(Block &forBlock, nlohmann::json &data)
{
    std::string result = "";
    std::string expression = forBlock.expression;
    std::string value = expression.substr(0, expression.find(" in "));
    std::string iterable = expression.substr(expression.find(" in ") + 4);

    auto range = process_range(iterable, data);
    long n = range.first;
    long m = range.second;

    if (n != 0 && m != 0)
    {
        for (long i = n; i < m; i++)
        {
            data[value] = i;
            result += this->__Render(forBlock, data);
        }
    }
    else if (data[iterable].is_array())
    {
        std::vector<nlohmann::json> values = data[iterable].get<std::vector<nlohmann::json>>();
        for (auto &item : values)
        {
            data[value] = item;
            result += this->__Render(forBlock, data);
        }
    }
    else if (data[iterable].is_object())
    {
        std::map<std::string, nlohmann::json> values = convertToMap(data, iterable);
        for (auto &item : values)
        {
            auto allData = data;
            if (data.contains(value))
                throw std::runtime_error("The variable " + value + " already exists in the data");
            allData[value] = item.second;
            nlohmann::json itemData = item;
            result += this->__Render(forBlock, itemData);
        }
    }
    else
    {
        auto it = accessJsonValue(data, iterable);
        if (it != nullptr)
        {
            if (it.is_array())
            {
                std::vector<nlohmann::json> values = it.get<std::vector<nlohmann::json>>();
                for (auto &item : values)
                {
                    data[value] = item;
                    result += this->__Render(forBlock, data);
                }
            }
            else if (it.is_object())
            {
                std::map<std::string, nlohmann::json> values = convertToMap(data, iterable);
                for (auto &item : values)
                {
                    auto allData = data;
                    if (data.contains(value))
                        throw std::runtime_error("The variable " + value + " already exists in the data");
                    allData[value] = item.second;
                    nlohmann::json itemData = item;
                    result += this->__Render(forBlock, itemData);
                }
            }
        }
        else
            throw std::runtime_error("The variable " + iterable + " is not an array or an object");
    }
    return result;
}

Block Templating::BlockParser(std::istream &stream, Block parent)
{
    std::string line;
    Block block;

    if (parent.type != BlockType::ROOT)
    {
        block = parent;
    }

    while (std::getline(stream, line))
    {
        std::smatch match;

        if (std::regex_search(line, match, statement_pattern))
        {
            std::string statement = match[1].str();

            if (std::regex_search(statement, match, include_pattern))
            {
                std::ifstream file(match[1].str());
                if (!file)
                {
                    std::cerr << "Error opening file: " << match[1].str() << std::endl;
                    return block;
                }

                Block newBlock;
                newBlock.type = BlockType::INCLUDE;
                newBlock.expression = match[1].str();
                newBlock.indexToPlace = block.content.size();
                newBlock = this->BlockParser(file, newBlock);
                block.children.push_back(newBlock);

                file.close();
            }
            else if (std::regex_search(statement, match, if_pattern))
            {
                Block newBlock;
                newBlock.type = BlockType::IF;
                newBlock.expression = match[1].str();
                newBlock.indexToPlace = block.content.size();
                newBlock = this->BlockParser(stream, newBlock);
                block.children.push_back(newBlock);
            }
            else if (std::regex_search(statement, match, for_pattern))
            {
                Block newBlock;
                newBlock.type = BlockType::FOR;
                newBlock.expression = match[1].str();
                newBlock.indexToPlace = block.content.size();
                newBlock = this->BlockParser(stream, newBlock);
                if (block.subBlocks.empty())
                    block.children.push_back(newBlock);
                else
                    block.subBlocks.back().children.push_back(newBlock);
            }
            else if (std::regex_search(statement, match, elif_pattern) && block.type == BlockType::IF)
            {
                if (SubBlockType::ELSE == block.subBlocks.back().type)
                    return block;
                SubBlock subBlock;
                subBlock.type = SubBlockType::ELIF;
                subBlock.expression = match[1].str();
                block.subBlocks.push_back(subBlock);
            }
            else if (std::regex_search(statement, match, else_pattern) && block.type == BlockType::IF)
            {
                // if sublocks length is greater than 0 and there is an else block, the last subblock must be an elif
                if (!block.subBlocks.empty())
                    if (SubBlockType::ELSE == block.subBlocks.back().type)
                        return block;
                SubBlock subBlock;
                subBlock.type = SubBlockType::ELSE;
                block.subBlocks.push_back(subBlock);
            }
            else if (std::regex_search(statement, match, endif_pattern) && block.type == BlockType::IF)
            {
                return block;
            }
            else if (std::regex_search(statement, match, endfor_pattern) && block.type == BlockType::FOR)
            {
                return block;
            }
        }
        else
        {
            if (!block.subBlocks.empty())
            {
                block.subBlocks.back().content.push_back(line);
            }
            else
            {
                block.content.push_back(line);
            }
        }
    }

    return block;
}

std::string Templating::__renderExpressions(std::string expression, nlohmann::json &data)
{

    std::string resultString;

    std::smatch match;

    if (std::regex_search(expression, match, expression_pattern))
    {
        std::string value = match[1].str();

        size_t matchPosition = match.position();
        std::string left = expression.substr(0, matchPosition);
        std::string right = expression.substr(matchPosition + match[0].length());
        right = this->__renderExpressions(right, data);
        resultString = left;
        double result = NAN;
        try
        {
            result = __evaluateExpression(value, data);
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
        }

        if (std::isnan(result))
        {
            if (std::regex_search(value, match, urlfor_pattern))
            {
                std::string url = match[2].str();
                try
                {
                    url = accessJsonValue(data, url).get<std::string>();
                }
                catch (const std::exception &e)
                {
                    url = match[2].str();
                }
                this->server->urlfor(url);
                resultString += url;
            }
            else
            {
                try
                {
                    auto result = accessJsonValue(data, value);
                    resultString += result.is_string() ? result.get<std::string>() : result.dump();
                }
                catch (const std::exception &e)
                {
                    resultString += value;
                }
            }
            resultString += right;
        }
        else
        {
            resultString += std::to_string(result) + right;
        }

        return resultString;
    }
    return expression;
}
