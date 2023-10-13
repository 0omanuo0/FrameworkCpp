#pragma once

#include <string>
#include <random>
#include <ctime>

class idGenerator
{
    public:
        static int generateID(){return atoi(generateIDstr().c_str());}
        static std::string generateIDstr(){
            char id[32];
            for (size_t i = 0; i < 32; i++)
                id[i] = static_cast<char>(std::rand() % 10) + '0';
            return std::string(id, 32);
        }
};

