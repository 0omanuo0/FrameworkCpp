#include <string>
#include <vector>

using namespace std;

struct user{
    string name;
    string pass;
};
struct post{
    user usr;
    string post;
};

user getUser(string name, vector<user> &USERS){
    for(auto &user : USERS)
        if(user.name == name) return user;
    return user();
}

string posts_to_string(vector<post> &posts){
    string str = "[";
    for(auto &post : posts)
        str += R"({"user": ")" + post.usr.name + R"(", "post": ")" + post.post + "\"}, ";
    str.erase(str.length() - 2);
    return str + "]";
}
