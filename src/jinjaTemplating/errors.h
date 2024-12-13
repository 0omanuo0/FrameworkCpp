#ifndef JINJATEMPLATING_ERRORS_H
#define JINJATEMPLATING_ERRORS_H

#include "types.h"

// render jinja errors
const std::unordered_map<BlockType, std::string> blockTypeToString = {
    {BlockType::FOR, "FOR"},
    {BlockType::IF, "IF"},
    {BlockType::ELSE, "ELSE"},
    {BlockType::INCLUDE, "INCLUDE"},
    {BlockType::ROOT, "ROOT"},
    {BlockType::SUBBLOCK, "SUBBLOCK"}};

const std::unordered_map<SubBlockType, std::string> subBlockTypeToString = {
    {SubBlockType::ELSE, "ELSE"},
    {SubBlockType::ELIF, "ELIF"}};

inline std::string convert_to_html(const std::string &msg)
{
    std::string html = msg;
    html = std::regex_replace(html, std::regex("&"), "&amp;");
    html = std::regex_replace(html, std::regex("<"), "&lt;");
    html = std::regex_replace(html, std::regex(">"), "&gt;");
    html = std::regex_replace(html, std::regex("\""), "&quot;");
    html = std::regex_replace(html, std::regex("'"), "&#39;");
    return html;
}

inline nlohmann::json block_to_json(const Block &block)
{
    nlohmann::json j_block;
    j_block["type"] = blockTypeToString.at(block.type); // Convertir BlockType a string
    j_block["expression"] = block.expression;
    j_block["indexToPlace"] = block.indexToPlace;
    j_block["content"] = nlohmann::json::array();
    for (const auto &content : block.content)
    {
        j_block["content"].push_back(convert_to_html(content));
    }

    j_block["subBlocks"] = nlohmann::json::array();
    for (const auto &subBlock : block.subBlocks)
    {
        nlohmann::json j_subBlock;
        j_subBlock["type"] = subBlockTypeToString.at(subBlock.type); // Convertir SubBlockType a string
        j_subBlock["expression"] = convert_to_html(subBlock.expression);
        j_subBlock["content"] = nlohmann::json::array();
        for (const auto &content : subBlock.content)
        {
            j_subBlock["content"].push_back(convert_to_html(content));
        }

        j_subBlock["children"] = nlohmann::json::array();
        for (const auto &child : subBlock.children)
        {
            j_subBlock["children"].push_back(block_to_json(child));
        }
        j_block["subBlocks"].push_back(j_subBlock);
    }

    j_block["children"] = nlohmann::json::array();
    for (const auto &child : block.children)
    {
        j_block["children"].push_back(block_to_json(child));
    }
    return j_block;
}

inline std::string intToHex(int value)
{
    std::stringstream ss;
    ss << std::hex << value;
    return ss.str();
}

inline std::string render_error(const std::string &msg, const StackTrace &stack_trace, std::string file, int line, nlohmann::json json_data = {}, const Block &block = Block())
{
#pragma region json_data_head
    std::string body = R"(
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap');

        body {
            font-family: 'Inter', sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f9fafb;
            color: #333;
            line-height: 1.6;
        }

        h1 {
            background-color: #ff6b6b;
            color: white;
            padding: 15px;
            margin: 0;
            font-size: 1.5rem;
            font-weight: 600;
        }

        h2 {
            background-color: #ff6b6b;
            color: white;
            padding: 10px;
            margin: 0;
            font-size: 1.25rem;
            font-weight: 600;
            padding-left: 50px;
        }

        p {
            padding: 15px;
            background-color: #fff;
            margin: 10px;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            position: relative;
        }

        p strong {
            font-weight: 600;
        }

        p span {
            position: absolute;
            bottom: 5px;
            right: 15px;
        }

        details {
            margin: 10px;
            padding: 15px;
            background-color: #fff;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }

        summary {
            padding: 10px;
            background-color: #ff6b6b;
            color: white;
            cursor: pointer;
            border-radius: 5px;
            font-weight: 600;
        }

        ul {
            list-style-type: none;
            padding: 0;
            margin: 10px 0;
        }

        li {
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.9rem;
            border: 1px solid #e2e8f0;
        }

        li:nth-child(odd) {
            background-color: #f1f5f9;
        }

        li:nth-child(even) {
            background-color: #e2e8f0;
        }

        li strong {
            color: #ff6b6b;
            font-weight: normal;
        }

        .footer {
            padding: 10px;
            text-align: center;
            font-size: 0.875rem;
            color: #555;
        }

        #debugger {
            margin: 10px;
            background-color: #fff;
            border-radius: 5px;
        }

        #debugger pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            background-color: #f9f9f9;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #e2e8f0;
        }

        #search-container {
            margin: 10px;
            display: flex;
            align-items: center;

        }

        #search {
            /* margin: 10px; */
            margin-top: 0px;
            margin-left: 30px;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #e2e8f0;
            width: 500px;
            height: fit-content;
            transition: cubic-bezier(0.4, 0, 0.2, 1) 0.1s;
            background-color: #f9f9f9;
        }

        #search:focus {
            outline: 2px solid #ff6b6b;
        }

        span.string {
            color: green;
        }

        span.number {
            color: darkorange;
        }

        span.boolean {
            color: blue;
        }

        span.null {
            color: magenta;
        }

        span.key {
            color: red;
        }

        #block-tree ul {
            list-style-type: none;
            padding-left: 20px;
        }

        #block-tree li {
            margin: 5px 0;
            cursor: pointer;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            border: none;
            padding: 5px 10px;
        }
        #block-tree li:first-child {
            margin-top: 0;
        }

        #block-tree li ul {
            display: none;
        }

        #block-tree li.open > ul {
            display: block;
        }
    </style>
    <link
        href="data:text/css,%3Ais(%5Bid*%3D'google_ads_iframe'%5D%2C%5Bid*%3D'taboola-'%5D%2C.taboolaHeight%2C.taboola-placeholder%2C%23credential_picker_container%2C%23credentials-picker-container%2C%23credential_picker_iframe%2C%5Bid*%3D'google-one-tap-iframe'%5D%2C%23google-one-tap-popup-container%2C.google-one-tap-modal-div%2C%23amp_floatingAdDiv%2C%23ez-content-blocker-container)%20%7Bdisplay%3Anone!important%3Bmin-height%3A0!important%3Bheight%3A0!important%3B%7D"
        rel="stylesheet" type="text/css">
</head>

<body>
    <h1>Error:)" + msg +
                       R"(</h1>
    <h2>File:)" + file +
                       ":" + std::to_string(line) + R"(</h2>
    <p>Sorry, something went wrong. This error occurred due to an issue in the application. Please check the stack trace below to identify the source of the problem. If this issue persists, contact support with the error details.
    <span><strong>Ver:</strong> jinjaTemplating 0.2a</span></p>
    <details>
        <summary>Stack Trace</summary>
        <ul>)";
#pragma endregion

#pragma region json_data_stack
    for (const auto &trace : stack_trace)
    { // trace.line is the offset from the start of the function, so needs to convert to hex
        body += "<li>" + convert_to_html(trace.func) + "<strong> at " + convert_to_html(trace.file) + ":0x" + intToHex(trace.line) + "</strong></li>";
    }
#pragma endregion

#pragma region json_data_vars
    body += R"(</ul>
    </details>
    <details>
        <summary>View Renderer Variables</summary>
        <div id="search-container">
            <h3>Search for a variable: </h3>
            <input id="search" type="text" placeholder="Search for a variable">
        </div>
        <div id="debugger"></div>
    </details>

    <script>
        // Assuming the renderer variables are passed as a JSON object
        const jsonVariables = )" +
            json_data.dump() + R"(;

        const debug = document.getElementById('debugger');
        const search = document.getElementById('search');

        search.value = "jsonVariables";

        search.addEventListener('input', function (e) {
            const searchValue = e.target.value;
            // execute the search
            let searchResult = '';
            try {
                searchResult = eval(searchValue);
            } catch (error) {
                searchResult = error.message;
            }
            try {
                debug.innerHTML = '<pre>' + syntaxHighlight(searchResult) + '</pre>';
            } catch (error) {
                debug.innerHTML = `<pre>${searchResult}</pre>`;
            }
        });

        debug.innerHTML = '<pre>' + syntaxHighlight(jsonVariables) + '</pre>';

        function syntaxHighlight(json) {
            if (typeof json != 'string') {
                json = JSON.stringify(json, undefined, 2);
            }
            json = json.replace(/&/g, '&').replace(/</g, '<').replace(/>/g, '>');
            return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*?"|true|false|null|-?(\d*\.)?\d+(?:[eE][+\-]?\d+)?)/g, function (match) {
                let cls = 'number';
                if (/^"/.test(match)) {
                    if (/:$/.test(match)) {
                        cls = 'key';
                    } else {
                        cls = 'string';
                    }
                } else if (/true|false/.test(match)) {
                    cls = 'boolean';
                } else if (/null/.test(match)) {
                    cls = 'null';
                }
                return '<span class="' + cls + '">' + match + '</span>';
            });
        }
    </script>
    )";
#pragma endregion

#pragma region json_data_blocks
    auto block_json = block_to_json(block);
    body += R"(
    <details >
        <summary>Tree View Template Blocks</summary>
        <div id="block-tree"></div>
    </details>
    <script>
        const jsonBlockData = )" +
            block_json.dump() + R"(;


        function createTreeView(container, data) {
            const ul = document.createElement('ul');
            container.appendChild(ul);

            for (const key in data) {
                if (data.hasOwnProperty(key)) {
                    const li = document.createElement('li');
                    // Establecer como abierto por defecto
                    if(data["indexToPlace"] == -1){
                        li.classList.add('open');
                    }

                    // Crear un span para la clave y establecerla en negrita
                    const keySpan = document.createElement('span');
                    keySpan.style.fontWeight = 'bold';
                    keySpan.textContent = key + ": ";
                    li.appendChild(keySpan);

                    if (typeof data[key] === 'object' && data[key] !== null) {
                        ul.appendChild(li);
                        createTreeView(li, data[key]);
                    } else {
                        // El valor se muestra como texto plano junto a la clave
                        const valueSpan = document.createElement('span');
                        valueSpan.textContent = data[key];
                        li.appendChild(valueSpan);
                        ul.appendChild(li);

                        // Si no tiene hijos, desactivar la selección
                        li.style.cursor = 'default';
                    }
                }
            }
        }


        const blockTree = document.getElementById('block-tree');
        createTreeView(blockTree, jsonBlockData);


        // Add click functionality to toggle the display of children
        blockTree.addEventListener('click', function (e) {
            const li = e.target;
            if (li.tagName === 'LI' && li.children.length > 0) {
                li.classList.toggle('open');
            }
        });
    </script>
    )";
#pragma endregion

    body += R"(
    <div class="footer">Thank you for your understanding.</div>
</body>
</html>)";

    return body;
}

#endif // JINJATEMPLATING_ERRORS_H
