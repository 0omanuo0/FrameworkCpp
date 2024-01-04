# FramworkCpp
 

The `HttpServer` library is a tool that allows you to create and configure an HTTP server capable of handling SSL requests. Here is a description of the main functions and classes available in this library:


## Features
- **HTTPS Support:**
        The library supports HTTPS with SSL/TLS encryption.

- **Multi-Threading:**
        It has built-in multi-threading support.

- **Variable Routes:**
        Allows the definition of routes with variables, enabling dynamic URL handling.

- **Static File Serving:**
        Supports serving static files such as images, CSS, and JavaScript files.

- **Template Rendering (Jinja):**
        Offers the ability to render Jinja or HTML templates, facilitating dynamic content generation.

- **Cookie and Session handling:**
        Includes features for finding and managing cookies in HTTP requests.

- **No Additional Libraries Required:**
    The library does not require any additional external libraries or dependencies, making it easy to integrate and use in various projects.
## Installation

Download the source code:

```bash
git clone https://github.com/0omanuo0/FramworkCpp.git
```
#### Requirements:

> The library requires only openssl and sqlite3
>
```bash
apt install libssl-dev libsqlite3-dev
```

For create a web server a makefile is provided:
- Build it with for debug: `$ make` or `$ make debug`
- Build for release: `$ make release`
- To clean the compiled binaries: `$ make clean`

## Documentation

[HttpServer class](src/server.h)

The `HttpServer` class is the main component of the library and is used to configure and manage an HTTP server.

### Builder

```cpp
HttpServer(int port_server, const string SSLcontext_server[], char *host = "0.0.0.0", int max_connections = 10);
```
This constructor is used to create an instance of `HttpServer` by specifying the server port, SSL context and other options such as host and maximum number of connections.


#### Start the Server
```cpp
void startListener();
```
This function is used to start the server and put it on standby to receive incoming requests.


#### Configure the Server
```cpp
int setup();
```
The `setup()` function is used to configure the server. It will return 0 if the configuration is successful.


#### Configure the 404 Page
```cpp
void setNotFound(string content);
```
With this feature, you can set the content of the custom 404 page that will be displayed when a valid route is not found.


#### Add Routes
```cpp
void addRoute(const string &path, function<string(Args &)> handler, vector<string> methods);
```
The `addRoute()` function allows you to add a new route to the server. You must specify the route in the browser, a handler function to handle the request, and the allowed methods to access the route.


#### Add Files

```cpp
void urlfor(const string &endpoint);
```
With this feature, you can add files to the server by specifying the file path.
#### Render Files

```cpp
string Render(const string &route, map<string, string> data = map<string, string>());
```
The `Render()` function is used to render a Jinja or HTML file and return it as a string to send to the client. You can pass additional data as a key-value map.

## Usage

All endpoints must be this way
```cpp
std::string _ENDPOINT_(Args &args)
```
Where `Args` has the following parameters:
```cpp
class Args
{
public:
     const std::vector<std::string> vars;
     const std::string query;
     httpMethods request;
     Session& session;
};
```

#### Args

- #### vars:
   This is a list containing all the values of the parameterized route. When a request arrives at the server with parameters in the URL for example, `"/user/<id>"`, these values are captured and stored in the vars list. You can access these values in the corresponding path handling function using args.vars.

- #### query:
   This is the query string of the HTTP request. The query string is usually found after the question mark in the URL for example, `"?search=keyword"`. You can access this string in the path handler function using args.query.

- #### request:
   The HTTP method of the request is stored here, such as `GET, POST, PUT, etc.` You can access this value in the route handler function using args.request.

   #### Contains the following:
   ```cpp
     std::string method;
     std::string route;
     std::string query;
     std::map<std::string, std::string> content;

     struct httpParams
     {
         std::string host;
         std::string user_agent;
         std::vector<std::string> accept;
         std::vector<std::string> accept_language;
         std::vector<std::string> accept_encoding;
         std::map<std::string, std::string> cookies;
         std::string DNT;
         std::string connection;
         std::string upgrade_insecure_requests;
         std::string content_type;
         std::string origin;
         std::string referer;


     };
     ```

- #### session:
   This is a reference to the client session. Session is a mechanism for storing data between HTTP requests.
   You can access session values using `args.session["<VALUE>"]`, where <VALUE> is the data key you want to retrieve or modify from the session.
   Also contains `Session.destroySession()` and `session.createSession()`


## Examples

```cpp
#include "src/server.h"

const int PORT = 8443;
const int MAX_CONNECTIONS = 500;

string HTTPScontext[] = {"secrets/cert.pem", "secrets/key.pem"};


HttpServer server(PORT, HTTPScontext, "ubuntu-manu.local", MAX_CONNECTIONS);

string user_account(Args &args)
{
     if (args.session["logged"] == "true" && args.vars[0] == args.session["user"])
         return server.Render("templates/user.html", {{"user", args.vars[0]}, {"pass", "password"});
     else
         return Redirect("/login");
}

/////your rest of code

int main(int argc, char **argv)
{
     server.addRoute("/user/<iuserid>", user_account, {GET, POST});
}
``` 

 
# UsersDB

The UsersDB class is an implementation of an SQLite database designed to handle user-related information.
### UsersDB constructor

```cpp
UsersDB(std::string file, bool create)
```
- Description: This is the constructor of the UsersDB class. It is used to create an instance of the SQLite database or open an existing one. You can specify the database file and whether to create it if it does not exist.
- Parameters:
         file: The name of the SQLite database file.
         create: A boolean flag that specifies whether to create the database if it does not exist.

#### getUsersName function

```cpp
std::vector<std::string> getUsersName()
```
- Description: This function retrieves the usernames stored in the database.
- Return: A vector of strings containing the usernames.

#### insertUser function

```cpp
void insertUser(const std::string &User)
````
- Description: Insert a new user into the database.
- Parameters:

modifyUser function

```cpp
void modifyUser(const std::string &User, const std::unordered_map<std::string, std::string> &data)
```
- Description: Modifies the data of an existing user in the database.
- Parameters:
         User: The name of the user to be modified.
         data: A map containing the data to be updated for the user.
- Use:

```cpp
     std::unordered_map<std::string, std::string> userData;
     userData["field1"] = "new_value";
     userData["field2"] = "another_new_value";
     database.modifyUser("ExistingUser", userData);
```

deleteUser function

```cpp
void deleteUser(const std::string &User)
```

### Operator [] UsersDB

The `[]` operator can be used to obtain or modify a database table, in addition to the `'Users'` table. Which allows you to operate in the following way:
- ``` int countRows()```;
- ``` vector<string> getFields();```
- ``` unordered_map<string, string> getByID(const string &idValue);```
- ``` vector<string> getByField(const string &fieldName, const string &fieldValue);```
- ``` unordered_map<string, string> getoneByField(const string &idColumnName, const string &idValue);```
- ``` void insertRow(const unordered_map<string, string> &data);```
- ``` void updateRow(const string &id, const unordered_map<string, string> &data);```
- ``` void deleteByID(const string &idValue);```

### Other Methods

The UsersDB class also includes other useful methods such as getFields, getUser, insertUsers, and more.
