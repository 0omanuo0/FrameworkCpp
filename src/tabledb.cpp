#include "usersdb.h"


std::vector<std::string> UsersDB::getAllTables()
{
    std::vector<std::string> tables;

    const char *query = "SELECT name FROM sqlite_master WHERE type='table';";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        throw db_error("Error preparing query to get tables");
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        const char *tableName = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        if (tableName)
        {
            tables.push_back(tableName);
        }
    }

    sqlite3_finalize(stmt);
    return tables;
}

void UsersDB::createTable(const std::string &tableName, const std::unordered_map<std::string, std::string> &columns)
{
    // Verificar si la tabla ya existe
    if (tableExists(tableName))
    {
        throw db_error("Table already exists");
    }

    // Construir la consulta SQL para crear la nueva tabla
    std::string createTableSQL = "CREATE TABLE " + tableName + " ( id INTEGER PRIMARY KEY AUTOINCREMENT, ";
    for (const auto &column : columns)
    {
        createTableSQL += column.first + " " + column.second + ", ";
    }
    createTableSQL = createTableSQL.substr(0, createTableSQL.length() - 2) + ");";

    // Ejecutar la consulta SQL
    int rc;
    rc = sqlite3_exec(db, createTableSQL.c_str(), 0, 0, 0);

    if (rc != SQLITE_OK)
    {
        throw db_error("Error creating new table");
    }
    updateTables();
    return;
}

bool UsersDB::tableExists(const std::string &tableName)
{
    const std::string checkTableSQL = "SELECT name FROM sqlite_master WHERE type='table' AND name=?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, checkTableSQL.c_str(), -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        throw db_error("Error preparing tableExists query");
    }

    rc = sqlite3_bind_text(stmt, 1, tableName.c_str(), -1, SQLITE_STATIC);

    if (rc != SQLITE_OK)
    {
        throw db_error("Error binding tableName");
    }

    rc = sqlite3_step(stmt);
    updateTables();

    if (rc == SQLITE_ROW)
    {
        // La tabla ya existe
        sqlite3_finalize(stmt);
        return true;
    }
    else if (rc == SQLITE_DONE)
    {
        // La tabla no existe
        sqlite3_finalize(stmt);
        return false;
    }
    else
    {
        // Error al ejecutar la consulta
        sqlite3_finalize(stmt);
        throw db_error("Error checking table existence");
    }
}

void UsersDB::table::ensureFieldExist(const std::unordered_map<std::string, std::string> &data)
{
    // Obtener las columnas existentes en la tabla
    columns = getFields();

    // Verificar si cada columna en el mapa de datos existe en la tabla
    for (auto &entry : data)
    {
        bool columnExists = false;
        for (const std::string &existingColumn : columns)
        {
            if (existingColumn == entry.first)
            {
                columnExists = true;
                break;
            }
        }

        if (!columnExists)
        {
            // La columna no existe en la tabla, créala
            addField(entry.first, "TEXT");
        }
    }
    return;
}

void UsersDB::table::addField(const std::string &field_name, const std::string &field_type)
{
    // Construir la consulta SQL para agregar una columna
    std::string addColumnSQL = "ALTER TABLE " + name + " ADD COLUMN " + field_name + " " + field_type + ";";

    // Ejecutar la consulta SQL para agregar la columna
    int rc;
    rc = sqlite3_exec(db, addColumnSQL.c_str(), 0, 0, 0);

    if (rc != SQLITE_OK)
    {
        throw db_error("Error adding column");
    }
    return;
}

std::vector<std::string> UsersDB::table::getFields()
{
    std::vector<std::string> nombresColumnas;

    // Consulta SQL para obtener los nombres de las columnas
    std::string consulta = "PRAGMA table_info(" + name + ");";

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

void UsersDB::table::insertRow(const std::unordered_map<std::string, std::string> &data)
{
    ensureFieldExist(data);
    // Construir la consulta SQL para insertar una fila en la tabla
    std::string insertRowSQL = "INSERT INTO " + name + " (";
    std::string valuesSQL = "VALUES (";
    for (const auto &entry : data)
    {
        insertRowSQL += entry.first + ", ";
        valuesSQL += "'" + entry.second + "', ";
    }

    // Eliminar las últimas comas y cerrar paréntesis
    insertRowSQL = insertRowSQL.substr(0, insertRowSQL.length() - 2) + ") ";
    valuesSQL = valuesSQL.substr(0, valuesSQL.length() - 2) + ");";

    insertRowSQL += valuesSQL;

    // Ejecutar la consulta SQL para insertar la fila
    int rc;
    rc = sqlite3_exec(db, insertRowSQL.c_str(), 0, 0, 0);

    if (rc != SQLITE_OK)
    {
        throw db_error("Error inserting row");
    }
    return;
}

std::unordered_map<std::string, std::string> UsersDB::table::getByID(const std::string &idValue)
{
    std::unordered_map<std::string, std::string> fila;
    std::string selectSQL = "SELECT * FROM " + name + " WHERE id = ?;";

    sqlite3_stmt *stmt;

    // Preparar la sentencia SQL
    int rc = sqlite3_prepare_v2(db, selectSQL.c_str(), -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        return fila; // Devolver un vector vacío en caso de error
    }

    // Asignar el valor del parámetro en la consulta SQL
    sqlite3_bind_text(stmt, 1, idValue.c_str(), -1, SQLITE_STATIC);

    // Ejecutar la consulta
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        // Obtener el número de columnas en el resultado
        int numColumnas = sqlite3_column_count(stmt);

        for (int i = 0; i < numColumnas; ++i)
        {
            const char *valor = reinterpret_cast<const char *>(sqlite3_column_text(stmt, i));
            if (valor != nullptr)
                fila[columns[i]] = std::string(valor);
            else
                fila[columns[i]] = "";
        }
    }

    // Finalizar la consulta
    sqlite3_finalize(stmt);

    return fila;
}

std::unordered_map<std::string, std::string> UsersDB::table::getoneByField(const std::string &field, const std::string &value)
{
    // Construir la consulta SQL para encontrar el ID por el campo y su valor
    std::string findIDSQL = "SELECT ID FROM " + name + " WHERE " + field + " = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, findIDSQL.c_str(), -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        throw db_error("Error preparing findByField query");
    }

    rc = sqlite3_bind_text(stmt, 1, value.c_str(), -1, SQLITE_STATIC);

    if (rc != SQLITE_OK)
    {
        throw db_error("Error binding value");
    }

    std::string idValue;

    rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW)
    {
        idValue = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
    }
    else if (rc != SQLITE_DONE)
    {
        // Error al ejecutar la consulta
        sqlite3_finalize(stmt);
        throw db_error("Error finding ID by field");
    }

    sqlite3_finalize(stmt);

    // Si se encontró el ID, llamamos a getByID para obtener la fila completa
    if (!idValue.empty())
    {
        return getByID(idValue);
    }
    else
    {
        // Si no se encontró el ID, retornamos un mapa vacío
        return std::unordered_map<std::string, std::string>();
    }
}

std::vector<std::string> UsersDB::table::getByField(const std::string &fieldName, const std::string &fieldValue)
{
    std::vector<std::string> matchingIDs;

    // Construir la consulta SQL para seleccionar los IDs donde el campo coincida con el valor
    std::string getIDsSQL = "SELECT id FROM " + name + " WHERE " + fieldName + " = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, getIDsSQL.c_str(), -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        throw db_error("Error preparing getIDs query");
    }

    rc = sqlite3_bind_text(stmt, 1, fieldValue.c_str(), -1, SQLITE_STATIC);

    if (rc != SQLITE_OK)
    {
        throw db_error("Error binding fieldValue");
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        const char *idValue = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        if (idValue)
        {
            matchingIDs.push_back(idValue);
        }
    }

    sqlite3_finalize(stmt);
    return matchingIDs;
}

void UsersDB::table::deleteByID(const std::string &idValue)
{
    // Construir la consulta SQL para eliminar la fila por ID
    std::string deleteRowSQL = "DELETE FROM " + name + " WHERE id = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, deleteRowSQL.c_str(), -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        throw db_error("Error preparing deleteRow query");
    }

    rc = sqlite3_bind_text(stmt, 1, idValue.c_str(), -1, SQLITE_STATIC);

    if (rc != SQLITE_OK)
    {
        throw db_error("Error binding idValue");
    }

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE)
    {
        // Error al ejecutar la consulta
        sqlite3_finalize(stmt);
        throw db_error("Error deleting row by ID");
    }

    sqlite3_finalize(stmt);
}

int UsersDB::table::countRows(){
    const std::string countSQL= "SELECT COUNT(*) FROM " + name + ";";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, countSQL.c_str(), -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        throw db_error("Error preparing countRows query");
    }

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW)
    {
        throw db_error("Error counting rows");
    }

    int rowCount = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    return rowCount;
}