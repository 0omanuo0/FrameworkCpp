#include <string>
#include <vector>
#include <unordered_map>
#include <sqlite3.h>
#include <stdexcept>
#include <filesystem>
#include <stdexcept>
#include <openssl/sha.h>
#include <openssl/evp.h>

#ifndef USER_DB
#define USER_DB
class UsersDB
{
private:
    class db_error : public std::runtime_error
    {
    public:
        db_error(const std::string &error) : std::runtime_error(error) {}
    };

    class table
    {
    private:
        sqlite3 *db;
        void ensureFieldExist(const std::unordered_map<std::string, std::string> &data);
        void addField(const std::string &field_name, const std::string &field_type);
    public:
        std::string name;
        std::vector<std::string> columns;
        int countRows();
        std::vector<std::string> getFields();
        std::unordered_map<std::string, std::string> getByID(const std::string &idValue);
        std::vector<std::string> getByField(const std::string &fieldName, const std::string &fieldValue);
        std::unordered_map<std::string, std::string> getoneByField(const std::string &idColumnName, const std::string &idValue);
        void insertRow(const std::unordered_map<std::string, std::string> &data);
        void updateRow(const std::string &id, const std::unordered_map<std::string, std::string> &data);
        void deleteByID(const std::string &idValue);
        table(sqlite3 *db_f, const std::string &table_name, const std::vector<std::string> &columns_f){
            db = db_f;
            name = table_name;
            columns = columns_f;
        }
    };

    sqlite3 *db;
    std::string db_path;
    std::string user_table = "User_Table";
    std::string user_column = "nombre";
    std::string last_error;

    std::vector<table> table_list;

    bool check_column(const std::string &column_name);
    void add_column(const std::string &column_name);

public:
    UsersDB(std::string file, bool create = true);
    std::vector<std::string> getUser(const std::string &User);
    std::vector<std::string> getUsersName();
    void deleteUser(const std::string &User);
    void insertUser(const std::string &User);
    void insertUser(const std::string &User, const std::unordered_map<std::string, std::string> &data);
    void insertUsers(const std::vector<std::string> &Users);
    void insertUsers(const std::vector<std::string> &Users, const std::vector<std::unordered_map<std::string, std::string>> &data);
    void modifyUser(const std::string &User, const std::unordered_map<std::string, std::string> &data);

    std::vector<std::string> getAllTables();
    std::vector<std::string> getFields();
    std::vector<std::string> getFields(const std::string &table_name);
    void createTable(const std::string &table_name, const std::unordered_map<std::string, std::string> &columns);
    bool tableExists(const std::string &table_name);

    table &operator[](const std::string &table_name)
    {
        for (table &t : table_list)
        {
            if (t.name == table_name)
                return t;
        }
        createTable(table_name, {});
        return this->operator[](table_name);
    }

    void updateTable(const std::string &table_name, const std::vector<std::string> &columns){
        for(auto &t : table_list){
            if(t.name == table_name){
                t.columns = columns;
                return;
            }
        }
        table_list.push_back(table(db, table_name, columns));
        return;
    }
    void updateTables()
    {
        for (auto &table : getAllTables())
        {
            updateTable(table, getFields(table));
        }
        return;
    }
    std::string getLastError();
    void close();
    ~UsersDB();
};


#endif