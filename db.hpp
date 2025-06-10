#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <sqlite3.h>
#include <stdexcept>
#include <filesystem>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <sys/stat.h>  // For checking file existence (optional for non-UNIX systems)
#include <cstring>

class SoriaDB
{
private:
    sqlite3 *db;

    // Custom exception class for database-related errors
    class db_error : public std::runtime_error
    {
    public:
        explicit db_error(const std::string &error)
            : std::runtime_error(error) {}
    };

    // Helper function to check if a file exists (if create=false is used)
    bool fileExists(const std::string &filename)
    {
        struct stat buffer;
        return (stat(filename.c_str(), &buffer) == 0);
    }

public:
    /**
     * Constructor
     * @param file    Path to the SQLite database file.
     * @param create  If true (default), will create the database if it doesn't exist.
     *                If false, will throw if the database file doesn't exist.
     */
    explicit SoriaDB(const std::string &file, bool create = true)
        : db(nullptr)
    {
        // If create=false and file doesn't exist, throw an error
        if (!create && !fileExists(file))
        {
            throw db_error("Database file does not exist and create=false: " + file);
        }

        // Use sqlite3_open_v2 for finer control:
        //   - SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE means read/write and create if it doesn’t exist
        //   - SQLITE_OPEN_READWRITE means read/write but not create
        int flags = (create) ? (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE) : (SQLITE_OPEN_READWRITE);

        int rc = sqlite3_open_v2(file.c_str(), &db, flags, nullptr);
        if (rc != SQLITE_OK)
        {
            std::string errMsg = "Error opening database: ";
            errMsg += sqlite3_errmsg(db);
            sqlite3_close(db);
            db = nullptr;
            throw db_error(errMsg);
        }
    }

    // Destructor to close the database connection
    ~SoriaDB()
    {
        if (db)
        {
            sqlite3_close(db);
            db = nullptr;
        }
    }

    /**
     * @brief Fetch a single row (as an unordered_map) for the given SQL query.
     *        If multiple rows match, only the first one is returned.
     *
     * @param query SQL statement with '?' placeholders.
     * @param args  Vector of parameter values that match the '?' placeholders.
     * @return A single row as an unordered_map<columnName, columnValue>.
     */
    std::unordered_map<std::string, std::string>
    fetchone(const std::string &query, const std::vector<std::string> &args = {})
    {
        std::unordered_map<std::string, std::string> result;

        // Prepare the statement
        sqlite3_stmt *stmt = nullptr;
        int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK)
        {
            std::string errMsg = "Error preparing statement: ";
            errMsg += sqlite3_errmsg(db);
            throw db_error(errMsg);
        }

        // Bind parameters
        rc = bindParameters(stmt, args);
        if (rc != SQLITE_OK)
        {
            sqlite3_finalize(stmt);
            std::string errMsg = "Error binding parameters: ";
            errMsg += sqlite3_errmsg(db);
            throw db_error(errMsg);
        }

        // Execute and fetch the first row
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW)
        {
            // Extract columns
            int colCount = sqlite3_column_count(stmt);
            for (int i = 0; i < colCount; ++i)
            {
                const char *colName = sqlite3_column_name(stmt, i);
                const unsigned char *colText = sqlite3_column_text(stmt, i);

                if (colName)
                {
                    result[colName] = (colText ? reinterpret_cast<const char *>(colText) : "NULL");
                }
            }
        }
        else if (rc != SQLITE_DONE)
        {
            // Some error occurred
            std::string errMsg = "Error stepping statement: ";
            errMsg += sqlite3_errmsg(db);
            sqlite3_finalize(stmt);
            throw db_error(errMsg);
        }

        // Clean up
        sqlite3_finalize(stmt);
        return result;
    }

    /**
     * @brief Fetch all rows (as a vector of unordered_maps) for the given SQL query.
     *
     * @param query SQL statement with '?' placeholders.
     * @param args  Vector of parameter values that match the '?' placeholders.
     * @return A vector of rows, each row is an unordered_map<columnName, columnValue>.
     */
    std::vector<std::unordered_map<std::string, std::string>>
    fetchall(const std::string &query, const std::vector<std::string> &args = {})
    {
        std::vector<std::unordered_map<std::string, std::string>> results;

        // Prepare the statement
        sqlite3_stmt *stmt = nullptr;
        int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK)
        {
            std::string errMsg = "Error preparing statement: ";
            errMsg += sqlite3_errmsg(db);
            throw db_error(errMsg);
        }

        // Bind parameters
        rc = bindParameters(stmt, args);
        if (rc != SQLITE_OK)
        {
            sqlite3_finalize(stmt);
            std::string errMsg = "Error binding parameters: ";
            errMsg += sqlite3_errmsg(db);
            throw db_error(errMsg);
        }

        // Execute and fetch all rows
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
        {
            std::unordered_map<std::string, std::string> row;
            int colCount = sqlite3_column_count(stmt);
            for (int i = 0; i < colCount; ++i)
            {
                const char *colName = sqlite3_column_name(stmt, i);
                const unsigned char *colText = sqlite3_column_text(stmt, i);

                if (colName)
                {
                    row[colName] = (colText ? reinterpret_cast<const char *>(colText) : "NULL");
                }
            }
            results.push_back(row);
        }

        if (rc != SQLITE_DONE)
        {
            // Some error occurred (other than finishing the rows)
            std::string errMsg = "Error stepping statement: ";
            errMsg += sqlite3_errmsg(db);
            sqlite3_finalize(stmt);
            throw db_error(errMsg);
        }

        // Clean up
        sqlite3_finalize(stmt);
        return results;
    }

    /**
     * @brief Execute a query (INSERT, UPDATE, DELETE, DDL, etc.) that doesn't return any rows.
     *
     * @param query SQL statement with '?' placeholders.
     * @param args  Vector of parameter values that match the '?' placeholders.
     */
    void exec(const std::string &query, const std::vector<std::string> &args = {})
    {
        // Prepare the statement
        sqlite3_stmt *stmt = nullptr;
        int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK)
        {
            std::string errMsg = "Error preparing statement: ";
            errMsg += sqlite3_errmsg(db);
            throw db_error(errMsg);
        }

        // Bind parameters
        rc = bindParameters(stmt, args);
        if (rc != SQLITE_OK)
        {
            sqlite3_finalize(stmt);
            std::string errMsg = "Error binding parameters: ";
            errMsg += sqlite3_errmsg(db);
            throw db_error(errMsg);
        }

        // Execute (step once)
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE)
        {
            // Some error occurred
            std::string errMsg = "Error stepping statement: ";
            errMsg += sqlite3_errmsg(db);
            sqlite3_finalize(stmt);
            throw db_error(errMsg);
        }

        // Clean up
        sqlite3_finalize(stmt);
    }

private:
    /**
     * @brief Helper function to bind parameters to a prepared statement.
     *        Returns SQLite error code. 
     *
     * @param stmt  Pointer to the prepared SQLite statement.
     * @param args  Vector of parameter values that match the '?' placeholders.
     * @return SQLite return code (e.g., SQLITE_OK, SQLITE_ERROR)
     */
    int bindParameters(sqlite3_stmt *stmt, const std::vector<std::string> &args)
    {
        // Number of placeholders in the prepared statement
        int paramCount = sqlite3_bind_parameter_count(stmt);

        // Check if arguments match the placeholders
        if (static_cast<int>(args.size()) != paramCount)
        {
            // We do NOT do the actual injection of strings manually,
            // so if the counts don't match, it's a usage error.
            return SQLITE_MISUSE; 
        }

        // Bind each parameter (as text by default)
        for (int i = 0; i < paramCount; ++i)
        {
            // SQLite bind parameters start at 1
            int rc = sqlite3_bind_text(
                stmt,
                i + 1,
                args[i].c_str(),
                static_cast<int>(args[i].size()),
                SQLITE_TRANSIENT // Tells SQLite to make its own copy
            );
            if (rc != SQLITE_OK)
            {
                return rc;
            }
        }

        return SQLITE_OK;
    }
};