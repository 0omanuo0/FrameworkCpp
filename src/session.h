#pragma once

#include "idGenerator.h"

using namespace std;

class Session
{
private:
    /* data */
public:
    string id;
    map<string, string> values;
    bool create;
    bool isEmpty()
    {
        return id.empty() ? true : false;
    }
    void addValue(string key, string value)
    {
        values.insert(make_pair(key, value));
    }
    void modifyValue(string key, string value)
    {
        values[key] = value;
    }
    void createSession()
    {
        if (isEmpty())
        {
            id = idGenerator::generateIDstr();
            create = true;
        }
    }
    string &operator[](string key)
    {
        return values[key];
    }

    Session() { create = false; }
    Session(string id_f) : id(id_f) { create = true; }
    Session(string id_f, string key, string value)
        : id(id_f)
    {
        values.insert(make_pair(key, value));
        create = true;
    }
};
