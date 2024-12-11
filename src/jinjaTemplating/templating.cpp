#include "templating.h"
#include "errors.h"

std::string Templating::RenderString(const std::string &content, const nlohmann::json &data)
{
    std::istringstream stream(content);
    Block rootBlock = this->BlockParser(stream);
    nlohmann::json dataCopy = data;
    return this->__Render(rootBlock, dataCopy);
}

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
    catch (const Templating_ParserError &e)
    {
        this->server->logger.error(e.what());
        return "";
    }
    catch (const Templating_RenderError &e)
    {
        this->server->logger.error(e.what());
        auto data_ = e.getData();
        if (data_.is_null())
            data_ = data;

        return render_error(e.what(), e.getStackTrace(), e.getFile(), e.getLine(), data_, root);
    }
    catch (const std::exception &e)
    {
        this->server->logger.error(e.what());
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

        for (auto &index : this->findChildren(block, lineN))
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
                throw Templating_ParserError("Invalid block type", block);
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
    // Lambda function to create a new Block from a SubBlock
    auto createBlock = [&](SubBlock &subBlock)
    {
        Block newBlock;
        newBlock.type = BlockType::SUBBLOCK;
        newBlock.content = subBlock.content;
        newBlock.children = subBlock.children;
        newBlock.compiledExpression.compile(subBlock.expression);
        return newBlock;
    };
    ifBlock.compiledExpression.set_variables(convert_to_variant_map(data));
    auto r = ifBlock.compiledExpression.eval().toNumber();
    // Evaluate the main ifBlock expression
    if ((bool)r)
    {
        return this->__Render(ifBlock, data);
    }
    else
    {
        // Iterate through subBlocks (ELIF and ELSE)
        for (auto &subBlock : ifBlock.subBlocks)
        {
            subBlock.compiledExpression.set_variables(convert_to_variant_map(data));

            if (subBlock.type == SubBlockType::ELIF && (bool)subBlock.compiledExpression.eval().toNumber())
            {
                auto newBlock = createBlock(subBlock);
                return this->__Render(newBlock, data);
            }
            else if (subBlock.type == SubBlockType::ELSE)
            {
                auto newBlock = createBlock(subBlock);
                return this->__Render(newBlock, data);
            }
            else
                throw Templating_RenderError("Invalid subblock type", ifBlock, {}, __builtin_FILE(), __builtin_LINE());
        }
    }
    return "";
}

std::string Templating::__renderForBlock(Block &forBlock, nlohmann::json &data)
{
    std::string result = "";
    std::string expression = forBlock.expression;
    std::string value = expression.substr(0, expression.find(" in "));
    std::string iterable = expression.substr(expression.find(" in ") + 4);

    // Handle range-based loops (e.g., "i in range(0, 10)")
    auto range = process_range(iterable, data);
    long n = range.first;
    long m = range.second;

    if (n >= 0 && m > 0 && n < m)
    {
        for (long i = n; i < m; i++)
        {
            data[value] = i;
            result += this->__Render(forBlock, data);
        }

        return result;
    }
    else if (n != -1 && m != -1)
        throw Templating_RenderError("Invalid range: " + iterable, forBlock, __builtin_FILE(), __builtin_LINE());

    // Handle JSON array or object-based loops
    // get the value and the filters
    auto exprEval = expr(expression);
    const auto data_as_map = data.get<std::unordered_map<std::string, nlohmann::json>>();
    exprEval.set_variables(convert_to_variant_map(data_as_map));
    exprEval.compile();
    const auto it = exprEval.eval();

    if (it.is_array())
    {
        // Iterate over JSON array
        auto values = it.toJson().get<std::vector<json_t>>();
        for (auto &item : values)
        {
            data[value] = item;
            result += this->__Render(forBlock, data);
        }
    }
    else if (it.is_object())
    {
        // Iterate over JSON object
        auto values = it.toJson().get<std::unordered_map<std::string, json_t>>();
        if (values.empty())
            throw Templating_RenderError("Invalid iterable: " + iterable + " is not an object", forBlock, __builtin_FILE(), __builtin_LINE(), data);
        for (auto &item : values)
        {
            auto allData = data;
            if (data.contains(value))
                throw std::runtime_error("The variable " + value + " already exists in the data");
            allData[value] = item.second;
            result += this->__Render(forBlock, allData);
        }
    }
    else if (it.isString())
    {
        // Iterate over characters in a string
        for (auto &item : it.toString())
        {
            data[value] = item;
            result += this->__Render(forBlock, data);
        }
    }
    else
        throw Templating_RenderError("Invalid iterable: " + iterable + " is not an array or an object", forBlock, __FILE__, __LINE__);

    return result;
}

Block Templating::BlockParser(std::istream &stream, Block parent)
{
    std::string line;
    Block block;

    auto createBlock = [&](BlockType type, int indexToPlace = -1, std::string expression = "")
    {
        Block newBlock;
        newBlock.type = type;
        newBlock.indexToPlace = indexToPlace;
        newBlock.expression = expression;
        newBlock.compiledExpression.compile(expression);
        return newBlock;
    };

    if (parent.type != BlockType::ROOT)
        block = parent;

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
                    throw std::filesystem::filesystem_error("Error opening file: " + match[1].str(), std::make_error_code(std::errc::no_such_file_or_directory));

                Block newBlock = createBlock(BlockType::INCLUDE, block.content.size(), match[1].str());
                newBlock = this->BlockParser(file, newBlock);
                block.children.push_back(newBlock);

                file.close();
            }
            else if (std::regex_search(statement, match, if_pattern))
            {
                Block newBlock = createBlock(BlockType::IF, block.content.size(), match[1].str());
                newBlock = this->BlockParser(stream, newBlock);
                block.children.push_back(newBlock);
            }
            else if (std::regex_search(statement, match, for_pattern))
            {
                Block newBlock = createBlock(BlockType::FOR, block.content.size(), match[1].str());
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
                subBlock.compiledExpression.compile(subBlock.expression);
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
            else if (std::regex_search(statement, match, endif_pattern) && block.type == BlockType::IF || std::regex_search(statement, match, endfor_pattern) && block.type == BlockType::FOR)
                return block;
            else
                throw Templating_ParserError("Invalid statement: " + statement, block);
        }
        else
        {
            if (!block.subBlocks.empty())
                block.subBlocks.back().content.push_back(line);
            else
                block.content.push_back(line);
        }
    }

    return block;
}

std::string Templating::__renderExpressions(std::string expression, nlohmann::json &data)
{

    std::string resultString;
    std::smatch match;
    // std::cout << data.dump() << std::endl;
    // Check if is a jinja expression. e.g., {{ expression }}
    if (std::regex_search(expression, match, expression_pattern))
    {
        std::string value = match[1].str();

        size_t matchPosition = match.position();
        std::string left = expression.substr(0, matchPosition);
        std::string right = expression.substr(matchPosition + match[0].length());

        // Check if there are more expressions in the right side
        if (!right.empty())
            right = this->__renderExpressions(right, data);
        resultString = left;

        const auto url_for_function = [this](const token_data_t *args) -> token_data_t
        {
            const int type = args[0].index();
            string_t path = "";
            if (type == 1)
            {
                path = std::get<string_t>(args[0]);
                if (path.empty())
                    return token_data_t(string_t(""));
            }
            else if (type == 2)
            {
                // auto a = std::get<json_t>(value).dump();
                path = std::get<json_t>(args[0]).dump();
                if (path.empty())
                    return token_data_t(string_t(""));
                path = (char)path[0] == '"' ? path.substr(1, path.size() - 2) : path;

                // return a;
            }
            else
                return token_data_t(string_t(""));

#ifdef SERVER_H
            if (this->server != nullptr)
                this->server->urlfor(path);
#endif
            return path;
        };

        // Evaluate the expression, it handles filters and variables from the json data
        expr expressionEval(value);
        auto a = convert_to_variant_map(data);
        expressionEval.set_variables(a);
        expressionEval.set_functions({{"urlfor", {url_for_function, 1}}});
        expressionEval.compile();
        const auto result = expressionEval.eval().toString(true);

        return resultString + result + right;
    }
    return expression;
}
