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

For create a web server a CMake platform is provided:

- Create a build directory and navigate into it: $ mkdir build && cd build
- Generate build files: `$ cmake ..`
- Build for debug: `$ cmake --build . --config Debug -- -j4`
- Build for release: `$ cmake --build . --config Release -- -j4`
- To clean the compiled binaries: `$ cmake --build . --target clean_all`

## Documentation

[HttpServer class](src/server.h)

The `HttpServer` class is the main component of the library and is used to configure and manage an HTTP server.

### Builder

```cpp
HttpServer(int port_server, const string SSLcontext_server[], char *host = "0.0.0.0");
```
This constructor is used to create an instance of `HttpServer` by specifying the server port, SSL context and other options such as host and maximum number of connections.


#### Start the Server
```cpp
void startListener();
```
This function is used to start the server and put it on standby to receive incoming requests.


#### Add Routes
```cpp
void addRoute(string path, function<HttpResponse(Request)> handler, vector<string> methods);
```
The `addRoute()` function allows you to add a new route to the server. You must specify the route in the browser, a handler function to handle the request, and the allowed methods to access the route.


#### Add Files

```cpp
void urlfor(const string &endpoint);
```
With this feature, you can add files to the server by specifying the file path.
#### Render Files

```cpp
std::string Render(const std::string &route, nlohmann::json data);
string Render(const string &route, map<string, string> data);
```
The `Render()` function is used to render a Jinja or HTML file and return it as a string to send to the client. You can pass additional data as a key-value map or a `JSON`

## Usage

All endpoints must be this way
```cpp
types::HttpResponse _ENDPOINT_(Request &request)
```
Where `Request` has the following parameters:
- Url parameters defined before `std::unordered_map<std::string, std::string> parameters;`

- The method of the request `std::string method;`
- The complete route without the query `std::string route;`
- The query as string `std::string query;` ### needs to be changed in future
- The headers as an object, can be used perator [] to get specific one `httpHeaders headers;`
- A class containing the request data, for example, from a form `Content content;`
- A better way to acces the form data `std::map<std::string, std::string> form;`
- The session parameters `Session& session;`
- `SSL *ssl;`
- `int socket;`

### Request

   #### Contains the following options:
   - #### Header:
        The headers can being consulted using the operator, also are always parsed as the easiest form to read the information.

        ```cpp
        header operator[] (const std::string &key);
        
        class header
        {
        public:

                bool isString() // std::string
                bool isList() // is a vector<string>
                bool isDict() // is a map<string, string>
                bool isPair() // is a pair<string, string>
                headerType getType() // returns the headerType::type specific
                T get() // to get a specific data type is as: header["header"].get<type>()

                // also exists getType() function for each specific case
        }

        ```

        Also exists getType() function for each specific case

- #### Cookies
    The Cookies are stored as a map:
    ```cpp
    std::map<std::string, std::string> cookies;
    ```

- #### Content:
    ```cpp
    
    class Content
    {
    public:
    
            bool isString() // std::string
            bool isDict() // is a map<string, string>
            bool isByteArray() // is a vector<char>
            bool isJson() // get as a nlohmann::json
            contentType getType() // returns the contentType::type specific
            T get() // to get a specific data type is as: conent.get<type>()
    }
    
    ```
    
    Also exists get"Type"() function for each specific case such as getString()

- #### Session:
   This is a reference to the client session. Session is a mechanism for storing data between HTTP requests.

   You can access session values using `args.session["<VALUE>"]`, where < VALUE> is the data key you want to retrieve or modify from the session.
   Also contains `Session.destroySession()` and `session.createSession()` for managing things like exit the session.
   
   The session is stored as JWT token to be consulted.
   ###### in the future will be added the option to select the type of cookie

### Using .env

   All the initial parameters such as the route of ssl certificate, the `max_connections` allowed can be parsed from a `.env` file in the same path as the `workdir`.


## Render

The `HttpServer` library includes functionality for rendering Jinja templates or HTML files, enabling dynamic content generation on the server.

### Render Files
To render a file, you use the Render function provided by the HttpServer class. This function takes the path to the template file and the data you want to pass to it. The data can be supplied in the form of a JSON object or a string.

Here are the three overloads of the Render function:

- `string Render(string route, nlohmann::json data );` 

- `string Render(string route, string data);`

- It also exists the `string RenderString(string content, nlohmann::json data)`

`data` is always optional

### Current Limitations

Currently, the rendering engine supports the following Jinja statements:

- include
- for
- if, including elif and else

Other statements and more complex type manipulations, such as string concatenation or more complex data types, are not yet implemented.

## Example
There is an example provided into `app.cpp` but here is a basic example:

```cpp
#include "src/server.h"

const int PORT = 8443;

string HTTPScontext[] = {"secrets/cert.pem", "secrets/key.pem"};


HttpServer server(PORT, HTTPScontext, "ubuntu-manu.local");

types::HttpResponse home(Request &req)
{
    if (req.method == POST)
    {
        if (req.session["logged"] == "true")
        {
            std::string user = req.session["user"];
            std::string form_post = req.form["f_data"];
            std::string newRow = nlohmann::json({{"autor", user}, {"content", form_post}});
            // DATABASE["POSTS"].insertRow(newRow.dump());
        }
        else
            return Response("Unauthorized", 401);
    }
        else if (req.method == GET)
    {
        if (req.session["logged"] == "true")
        {
            // get the posts from the database
            nlohmann::json data = {{"user", req.session["user"]}, {"posts", POSTS}};
            return server.Render("templates/home_logged.html", data);
        }
        else
            return Redirect("/login");
    }
}

/* --- The rest of your code --- */

int main(int argc, char **argv)
{
     server.addRoute("/home", home, {GET, POST});
     // the route parameters are designed the following way:
     // Example: server.addRoute("/image/<id>", images, {GET});
}
``` 


