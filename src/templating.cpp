#include "templating.h"

namespace fs = filesystem;
using namespace std;

const json* navigate_json(const json* root, const vector<string>& path) {
    const json* current = root;

    for (const auto& key : path) {
        if (current->find(key) != current->end()) current = &(*current)[key];
        else return nullptr;
    }

    return current;
}

vector<string> splitAttributes(const string& input) {
    vector<string> result;
    istringstream iss(input);
    string token;

    while (getline(iss, token, '.'))
        result.push_back(token);

    return result;
}

void ListFilesAndFolders(const fs::path &directory, int level = 0)
{
    for (const auto &entry : fs::directory_iterator(directory))
    {
        const string filename = entry.path().filename().string();
        const string indentation = string(level * 4, ' ');

        if (fs::is_directory(entry.status()) && filename[0] != '.') // Ignore hidden folders (starting with .)
        {
            cout << indentation << "[Folder] " << filename << endl;
            ListFilesAndFolders(entry.path(), level + 1);
        }
        else if (fs::is_regular_file(entry.status()))
        {
            cout << indentation << "[File] " << filename << endl;
        }
    }
}

double Templating::__evaluate_expression(string expression, const map<string, string> &data)
{
    // Crear un conjunto de te_variable a partir del mapa
    set<te_variable> variablesSet;

    for (const auto &pair : data)
    {
        te_variable var;
        var.m_name = pair.first;

        try
        {
            var.m_value = stod(pair.second); // Convertir el valor a double
            var.m_type = TE_DEFAULT;
            variablesSet.insert(var);
        }
        catch (const exception &e)
        {
            return numeric_limits<double>::quiet_NaN();
        }
    }
    // Store variable names and pointers.
    te_parser tep;
    tep.set_variables_and_functions(variablesSet);

    if (tep.compile(expression))
        return tep.evaluate();
    else
        return numeric_limits<double>::quiet_NaN();
}

// Function that returns an string array ["a", "b", "c"] from a string "[a, b, c]" if not, returns an empty array
vector<string> FindArray(const string &content)
{       
    json j = json::parse(content);

    if(j.is_array()){
        std::vector<std::string> stringVector;
        for (const auto& elem : j) {
            stringVector.push_back(elem.dump());
        }
        return stringVector;
    }
    return {};
}

string Templating::__find_expressions(string line, const map<string, string> &data)
{

    string lineF;

    // Definimos una expresión regular para buscar patrones del tipo {{algo}}
    smatch matches;

    // Creamos iteradores para buscar todas las coincidencias de la expresión regular en la línea de entrada
    auto it = sregex_iterator(line.begin(), line.end(), expression_pattern);
    auto end = sregex_iterator();
    size_t currentPosition = 0;

    // Iteramos sobre todas las coincidencias encontradas
    for (; it != end; ++it)
    {
        // Obtenemos la coincidencia actual
        smatch match = *it;

        // Obtenemos la posición de la coincidencia en la línea de entrada
        size_t matchPosition = match.position();

        // Extraemos el texto antes de la coincidencia y lo agregamos al resultado
        string textBeforeMatch = line.substr(currentPosition, matchPosition - currentPosition);
        if (!textBeforeMatch.empty())
            lineF += textBeforeMatch;

        // Extraemos el contenido dentro de las llaves {{...}}
        string find = match[1].str();

        double result = __evaluate_expression(find, data);

        if (isnan(result))
        {
            smatch match_f;

            // Comprobamos si el contenido dentro de las llaves tiene el formato urlfor(algo)
            if (regex_search(find, match_f, patron_urlfor))
            {
                // Extraemos el contenido entre los paréntesis de urlfor y lo agregamos al resultado
                string path = match_f[1].str().substr(1, match_f[1].str().length() - 2);
                server->urlfor(path);
                lineF += path;
            }
            else
            {
                vector<string> path = splitAttributes(find);
                if(path.size() <= 1){
                    // Si no es del formato urlfor(algo), verificamos si el contenido se encuentra en el mapa 'data'
                    if (data.find(find) != data.end())
                        lineF += data.find(find)->second; // Agregamos el valor asociado a la clave 'find' al resultado
                    else
                        lineF += find; // Si no se encuentra en el mapa 'data', agregamos el contenido original al resultado
                }
                else{
                    json d; // Parse the JSON string
                    d[data.begin()->first] = json::parse(data.begin()->second);
                    const json* result = navigate_json(&d, path);

                    if (result) 
                        lineF += result->dump().substr(1, result->dump().length() - 2);
                    else 
                        lineF += find;
                }
            }
        }
        else
        {
            if (result == static_cast<int>(result))
                lineF += to_string(static_cast<int>(result));
        }

        // Actualizamos la posición actual para continuar buscando después de la coincidencia actual
        currentPosition = matchPosition + match.length();
    }

    // Agregamos el texto después de la última coincidencia al resultado final
    string textAfterLastMatch = line.substr(currentPosition);
    if (!textAfterLastMatch.empty())
        lineF += textAfterLastMatch;

    // Devolvemos la cadena resultante con todas las sustituciones y modificaciones realizadas
    return lineF;
}

// This function takes a file path and a map of data as input and returns a rendered string.
string Templating::__render_block(const string &path, const map<string, string> &data)
{
    // Check if the specified file path exists.
    if (!filesystem::exists(path))
    {
        // If the file doesn't exist, print an error message and list files and folders in the current directory.
        cout << "file does not exist" << endl;
        ListFilesAndFolders("."); // Assuming ListFilesAndFolders is a defined function elsewhere.
        return "";                // Return an empty string since rendering is not possible.
    }

    // Open the specified file for reading.
    ifstream file(path);
    string rendered;

    // Check if the file is successfully opened.
    if (file.is_open())
    {
        string line;
        getline(file, line);

        // Find the start of the block content in the file.
        while (!regex_search(line, block_pattern))
            getline(file, line);

        // Process lines within the block until the end of the block is reached.
        while (getline(file, line) && !regex_search(line, endblock_pattern))
        {
            // Replace expressions in the line using data from the map.
            line = __find_expressions(line, data); // Assuming __find_expressions is defined elsewhere.

            // Append processed line to the rendered content.
            rendered += __find_statements(line, file, data); // Assuming __find_statements is defined elsewhere.
        }

        // Close the file after processing.
        file.close();
    }
    else
        // Return an empty string if the file couldn't be opened.
        return "";

    // Return the rendered content.
    return rendered;
}

string Templating::__render_statements(string find, const map<string, string> &data)
{
    string lineF;

    smatch match_f;

    // Comprobamos si el contenido dentro de las llaves tiene el formato 'include "data" '
    if (regex_search(find, match_f, patron_include))
    {
        // Extraemos el contenido entre comillas
        string path = match_f[1].str();
        lineF = __render_block(path, data);
        if (lineF.empty())
            lineF = "Error al cargar el archivo";
    }
    else
        return find; // Si no se encuentra en el mapa 'data', agregamos el contenido original al resultado
    return lineF;
}

string Templating::__render_for(string find, ifstream &file, const map<string, string> &data)
{
    string rendered; // Will store the final rendered content of the 'for' loop.

    // Check if the provided file is open.
    if (!file.is_open())
    {
        cout << "error opening file" << endl; // Print an error message.
        ListFilesAndFolders(".");             // Call a function to list files and folders in the current directory (implementation not shown).
        return "";                            // Return an empty string since rendering is not possible.
    }

    smatch match_f;
    // Use a regular expression to search for the 'for' pattern in the 'find' string.
    if (!regex_search(find, match_f, for_pattern))
        return ""; // Return an empty string if the 'for' pattern is not found.

    string item_array[2] = {match_f[1].str(), match_f[2].str()}; // Extracted values from the pattern.
    vector<string> content;                                      // Will store the content of the array corresponding to the 'for' loop.

    // Iterate through the provided data map to find a match for the specified key.
    for (auto it : data)
    {
        if (it.first == item_array[1])
        {
            content = FindArray(it.second); // Call a function to find an array by the key (implementation not shown).
            if (content.empty())
                return ""; // Return an empty string if the array is empty.
            break;
        }
    }
    streampos for_pos = file.tellg(); // Get the current position in the file for later seeking.

    // Iterate through the 'content' vector, which represents the items in the array.
    for (auto &it : content)
    {
        file.seekg(for_pos); // Seek to the position where the 'for' loop starts in the file.

        string line;
        smatch match_f;

        // Read lines from the file until the 'endfor' pattern is encountered.
        while (getline(file, line) && !regex_search(line, endfor_pattern))
        {
            line = __find_expressions(line, {{item_array[0], it}});           // Call a function to replace expressions (implementation not shown).
            rendered += __find_statements(line, file, {{item_array[0], it}}); // Call a function to process statements (implementation not shown).
        }
    }

    return rendered; // Return the fully rendered content of the 'for' loop.
}

string Templating::__render_if(string find, ifstream &file, const map<string, string> &data)
{
    string rendered, line;

    if (!file.is_open())
    {
        cout << "error opening file" << endl;
        ListFilesAndFolders(".");
        return "";
    }

    smatch match_f;

    if (!regex_search(find, match_f, if_pattern))
        return "";

    string expression = match_f[1].str();
    if ((bool)__evaluate_expression(expression, data))
    {
        while (getline(file, line) && !regex_search(line, endif_pattern))
        {
            if (regex_search(line, else_pattern))
            {
                while (getline(file, line) && !regex_search(line, endif_pattern))
                    continue;
                break;
            }
            line = __find_expressions(line, data);
            rendered += __find_statements(line, file, data);
        }
    }
    else
    {
        while (getline(file, line) && !regex_search(line, else_pattern))
            continue;

        while (getline(file, line) && !regex_search(line, endif_pattern))
        {
            line = __find_expressions(line, data);
            rendered += __find_statements(line, file, data);
        }
    }

    return rendered;
}

string Templating::__find_statements(string line, ifstream &file, const map<string, string> &data)
{
    string lineF;

    // Definimos una expresión regular para buscar patrones del tipo {{algo}}
    smatch matches;

    // Creamos iteradores para buscar todas las coincidencias de la expresión regular en la línea de entrada
    auto it = sregex_iterator(line.begin(), line.end(), statement_pattern);
    auto end = sregex_iterator();
    size_t currentPosition = 0;

    // Iteramos sobre todas las coincidencias encontradas
    for (; it != end; ++it)
    {
        // Obtenemos la coincidencia actual
        smatch match = *it;

        // Obtenemos la posición de la coincidencia en la línea de entrada
        size_t matchPosition = match.position();

        // Extraemos el texto antes de la coincidencia y lo agregamos al resultado
        string textBeforeMatch = line.substr(currentPosition, matchPosition - currentPosition);
        if (!textBeforeMatch.empty())
            lineF += textBeforeMatch;

        // Extraemos el contenido dentro de las llaves {% ... %}
        string find = match[1].str();

        if (find.substr(0, find.find(" ")) == "for")
        {
            lineF += __render_for(find, file, data);
        }
        else if (find.substr(0, find.find(" ")) == "if")
        {
            lineF += __render_if(find, file, data);
        }
        else if (find.substr(0, find.find(" ")) == "endfor")
        {
        }
        else
        {
            lineF += __render_statements(find, data);
        }

        // Actualizamos la posición actual para continuar buscando después de la coincidencia actual
        currentPosition = matchPosition + match.length();
    }
    // Agregamos el texto después de la última coincidencia al resultado final
    string textAfterLastMatch = line.substr(currentPosition);
    if (!textAfterLastMatch.empty())
        lineF += textAfterLastMatch;

    // Devolvemos la cadena resultante con todas las sustituciones y modificaciones realizadas
    return lineF;
}

string Templating::Render(const string &route, const map<string, string> &data)
{
    if (server == nullptr)
    {
        cout << "Server not initialized, error pointer reference" << endl;
        return "";
    }
    if (!filesystem::exists(route))
    {
        cout << "file does not exist" << endl;
        ListFilesAndFolders(".");
        return "";
    }

    ifstream file(route);
    string rendered;
    if (file.is_open())
    {
        string line;
        while (getline(file, line))
        {
            line = __find_expressions(line, data);
            rendered += __find_statements(line, file, data);
        }
        file.close();
    }
    else
        return "";
    return rendered;
}
