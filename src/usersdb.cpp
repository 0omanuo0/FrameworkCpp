#include "usersdb.h"

std::string crypto_lib::calculateSHA512(const std::string &input)
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
    for (unsigned int i = 0; i < md_len; i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", md_value[i]);
        result += hex;
    }

    return result;
}

bool UsersDB::check_column(const std::string &column_name)
{
    // Check if the column already exists
    std::string checkColumnSQL = "PRAGMA table_info(" + user_table + ");";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, checkColumnSQL.c_str(), -1, &stmt, 0) != SQLITE_OK)
    {
        // Handle the error (e.g., throw an exception)
        throw db_error("Error preparing SQL statement");
    }

    bool columnExists = false;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        const char *colName = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        if (colName && std::string(colName) == column_name)
        {
            columnExists = true;
            break;
        }
    }
    sqlite3_finalize(stmt);
    return columnExists;
}
void UsersDB::add_column(const std::string &column_name)
{
    // Column does not exist, so add it
    const std::string addColumnSQL = "ALTER TABLE " + user_table + " ADD COLUMN " + column_name + " TEXT;";
    int rc = sqlite3_exec(db, addColumnSQL.c_str(), 0, 0, 0);
    if (rc != SQLITE_OK)
    {
        // Handle the error (e.g., throw an exception)
        throw db_error("Error creating the new column");
    }
    return;
}

UsersDB::~UsersDB() { close(); }
void UsersDB::close() { sqlite3_close(db); }

std::vector<std::string> UsersDB::getFields()
{
    std::vector<std::string> nombresColumnas;

    // Consulta SQL para obtener los nombres de las columnas
    std::string consulta = "PRAGMA table_info(" + user_table + ");";

    // Ejecutar la consulta
    sqlite3_stmt *stmt;
    int resultado = sqlite3_prepare_v2(db, consulta.c_str(), -1, &stmt, nullptr);

    if (resultado == SQLITE_OK)
    {
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            // Obtener el nombre de la columna y agregarlo al vector
            const char *nombreColumna = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            nombresColumnas.push_back(nombreColumna);
        }

        // Liberar el statement después de usarlo
        sqlite3_finalize(stmt);
    }
    else
    {
        // Error al preparar la consulta
        throw db_error("Error al obtener nombres de columnas: " + std::string(sqlite3_errmsg(db)));
    }

    return nombresColumnas;
}
std::vector<std::string> UsersDB::getFields(const std::string &table_name)
{
    std::vector<std::string> nombresColumnas;

    // Consulta SQL para obtener los nombres de las columnas
    std::string consulta = "PRAGMA table_info(" + table_name + ");";

    // Ejecutar la consulta
    sqlite3_stmt *stmt;
    int resultado = sqlite3_prepare_v2(db, consulta.c_str(), -1, &stmt, nullptr);

    if (resultado == SQLITE_OK)
    {
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            // Obtener el nombre de la columna y agregarlo al vector
            const char *nombreColumna = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            nombresColumnas.push_back(nombreColumna);
        }

        // Liberar el statement después de usarlo
        sqlite3_finalize(stmt);
    }
    else
    {
        // Error al preparar la consulta
        throw db_error("Error al obtener nombres de columnas: " + std::string(sqlite3_errmsg(db)));
    }

    return nombresColumnas;
}

std::vector<std::string> UsersDB::getUser(const std::string &User)
{
    std::vector<std::string> fila;
    std::string selectSQL;
    try
    {
        std::stoi(User);
        selectSQL = "SELECT * FROM " + user_table + " WHERE ?;";
    }
    catch (const std::invalid_argument &)
    {
        selectSQL = "SELECT * FROM " + user_table + " WHERE " + user_column + " = ?;";
    }

    sqlite3_stmt *stmt;

    // Preparar la sentencia SQL
    int rc = sqlite3_prepare_v2(db, selectSQL.c_str(), -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        return fila; // Devolver un vector vacío en caso de error
    }

    // Asignar el valor del parámetro en la consulta SQL
    sqlite3_bind_text(stmt, 1, User.c_str(), -1, SQLITE_STATIC);

    // Ejecutar la consulta
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        // Obtener el número de columnas en el resultado
        int numColumnas = sqlite3_column_count(stmt);

        for (int i = 0; i < numColumnas; ++i)
        {
            const char *valor = reinterpret_cast<const char *>(sqlite3_column_text(stmt, i));
            if (valor != nullptr)
                fila.push_back(valor);
            else
                fila.push_back(std::string());
        }
    }

    // Finalizar la consulta
    sqlite3_finalize(stmt);

    return fila;
}

void UsersDB::insertUsers(const std::vector<std::string> &Users)
{
    for (auto &user : Users)
        insertUser(user);
    return;
}

void UsersDB::insertUsers(const std::vector<std::string> &Users, const std::vector<std::unordered_map<std::string, std::string>> &data)
{
    for (size_t i{0}; i < Users.size(); i++)
        insertUser(Users[i], data[i]);
    return;
}

void UsersDB::insertUser(const std::string &User, const std::unordered_map<std::string, std::string> &data)
{
    if (!getUser(User).empty())
        throw db_error("User already exists");

    std::string insertSQL = "INSERT INTO " + user_table + " (" + user_column + ", ";
    std::string placeholders = "VALUES (?, ";
    int rc;

    for (const auto &item : data)
    {
        if (!check_column(item.first))
            add_column(item.first);

        insertSQL += item.first + ", ";
        placeholders += "?, ";
    }

    insertSQL = insertSQL.substr(0, insertSQL.length() - 2) + ")";
    placeholders = placeholders.substr(0, placeholders.length() - 2) + ")";

    insertSQL += placeholders;

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, insertSQL.c_str(), -1, &stmt, 0);

    if (rc != SQLITE_OK)
        throw db_error("Error preparing insert statement");

    rc = sqlite3_bind_text(stmt, 1, User.c_str(), -1, SQLITE_STATIC);

    if (rc != SQLITE_OK)
        throw db_error("Error binding username");

    int paramIndex = 2;
    for (const auto &item : data)
    {
        rc = sqlite3_bind_text(stmt, paramIndex, item.second.c_str(), -1, SQLITE_STATIC);
        if (rc != SQLITE_OK)
            throw db_error("Error binding parameter " + std::to_string(paramIndex - 1));
        paramIndex++;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        throw db_error("Error inserting new user");

    return;
}

void UsersDB::modifyUser(const std::string &User, const std::unordered_map<std::string, std::string> &data)
{
    std::string id;
    std::vector<std::string> userData = getUser(User);
    if (!userData.empty())
        id = userData[0];
    else
        throw db_error("User not found");

    const std::string sqlStatement = "DELETE FROM students WHERE id = " + id + ";";

    std::string insertSQL = "UPDATE " + user_table + " SET ";
    int rc;
    for (auto &item : data)
    {
        if (!check_column(item.first))
            add_column(item.first);
        // Now you can proceed with your other operations (inserting values into the table)
        insertSQL += item.first + " = '" + item.second + "', ";
    }

    insertSQL = insertSQL.substr(0, insertSQL.length() - 2);
    insertSQL += " WHERE " + id + ";";

    // Ejecutar la sentencia SQL para insertar valores
    rc = sqlite3_exec(db, insertSQL.c_str(), 0, 0, 0);

    if (rc != SQLITE_OK)
        throw db_error("Error while inserting new user");
    return;
}

void UsersDB::deleteUser(const std::string &User)
{
    std::vector<std::string> user = getUser(User);
    if (user.empty())
        throw db_error("User not exist");

    const std::string sqlStatement = "DELETE FROM " + user_table + " WHERE " + user[0] + ";";
    int rc = sqlite3_exec(db, sqlStatement.c_str(), 0, 0, 0);
    if (rc != SQLITE_OK)
        throw db_error("Error while removing user");
    return;
}

void UsersDB::insertUser(const std::string &User)
{
    if (!getUser(User).empty())
        throw db_error("User already exists");

    const std::string insertDataSQL = "INSERT INTO " + user_table + " (" + user_column + ") VALUES (?);";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, insertDataSQL.c_str(), -1, &stmt, 0);

    if (rc != SQLITE_OK)
        throw db_error("Error preparing insert statement");

    rc = sqlite3_bind_text(stmt, 1, User.c_str(), -1, SQLITE_STATIC);

    if (rc != SQLITE_OK)
        throw db_error("Error binding username");

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        throw db_error("Error inserting new user");

    return;
}

std::vector<std::string> UsersDB::getUsersName()
{
    // Sentencia SQL para seleccionar datos de la tabla
    const std::string selectSQL = "SELECT id, " + user_column + " FROM " + user_table + ";";

    sqlite3_stmt *stmt;
    std::vector<std::string> Users;

    // Preparar la sentencia SQL
    int rc = sqlite3_prepare_v2(db, selectSQL.c_str(), -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        last_error = sqlite3_errmsg(db);
        throw std::runtime_error("Error reading users");
    }
    else
    {
        int status = sqlite3_step(stmt);
        // Ejecutar la consulta
        while (status == SQLITE_ROW && status != SQLITE_DONE)
        {
            Users.push_back(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1)));
            status = sqlite3_step(stmt);
        }
        // Finalizar la consulta y cerrar la base de datos
        sqlite3_finalize(stmt);
        return Users;
    }
}

UsersDB::UsersDB(std::string file, bool create)
{
    db_path = file;
    // Intentar abrir la base de datos
    int rc = sqlite3_open(db_path.c_str(), &db);
    if (!std::filesystem::exists(db_path) && !create)
        throw std::runtime_error("File " + db_path + " does not exist");

    if (rc)
        throw std::runtime_error("Error opening db");

    // Sentencia SQL para crear la tabla (si no existe)
    const std::string createTableSQL = "CREATE TABLE IF NOT EXISTS " + user_table + " (id INTEGER PRIMARY KEY, " + user_column + " TEXT);";

    // Ejecutar la sentencia SQL para crear la tabla
    rc = sqlite3_exec(db, createTableSQL.c_str(), 0, 0, 0);

    if (rc != SQLITE_OK)
        throw std::runtime_error("Error creating db");

    updateTables();
}