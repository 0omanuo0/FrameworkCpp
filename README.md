# FramworkCpp
 

La librería `HttpServer` es una herramienta que te permite crear y configurar un servidor HTTP con capacidad para manejar solicitudes SSL. Aquí tienes una descripción de las principales funciones y clases disponibles en esta librería:


## Documentación

[Clase HttpServer](src/server.h)

La clase `HttpServer` es el componente principal de la librería y se utiliza para configurar y gestionar un servidor HTTP.

### Constructor

```cpp
HttpServer(int port_server, const string SSLcontext_server[], char *host = "0.0.0.0", int max_connections = 10);
```
Este constructor se utiliza para crear una instancia de `HttpServer` especificando el puerto del servidor, el contexto SSL y otras opciones como el host y el número máximo de conexiones.


#### Iniciar el Servidor
```cpp
void startListener();
```
Esta función se utiliza para iniciar el servidor y ponerlo en espera para recibir solicitudes entrantes.


#### Configurar el Servidor
```cpp
int setup();
```
La función `setup()` se utiliza para configurar el servidor. Devolverá 0 si la configuración se realiza correctamente.


#### Configurar la Página 404
```cpp
void setNotFound(string content);
```
Con esta función, puedes establecer el contenido de la página 404 personalizada que se mostrará cuando no se encuentre una ruta válida.


#### Agregar Rutas
```cpp
void addRoute(const string &path, function<string(Args &)> handler, vector<string> methods);
```
La función `addRoute()` te permite agregar una nueva ruta al servidor. Debes especificar la ruta en el navegador, una función de controlador para manejar la solicitud y los métodos permitidos para acceder a la ruta.


#### Agregar Archivos

```cpp
void urlfor(const string &endpoint);
```
Con esta función, puedes agregar archivos al servidor especificando la ruta del archivo.
#### Renderizar Archivos

```cpp
string Render(const string &route, map<string, string> data = map<string, string>());
```
La función `Render()` se utiliza para renderizar un archivo Jinja o HTML y devolverlo como una cadena para enviarlo al cliente. Puedes pasar datos adicionales como un mapa de claves y valores.

## Usage

Todos los endpoint deben de ser de esta menera
```cpp
std::string _ENDPOINT_(Args &args)
```
Donde `Args` tiene los siguientes parametros:
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
  Esta es una lista que contiene todos los valores de la ruta con parámetros. Cuando una solicitud llega al servidor con parámetros en la URL por ejemplo, `"/user/<id>"`, estos valores se capturan y se almacenan en la lista vars. Puedes acceder a estos valores en la función de manejo de ruta correspondiente utilizando args.vars.

- #### query:
  Esta es la cadena de consulta de la solicitud HTTP. La cadena de consulta generalmente se encuentra después del signo de interrogación en la URL por ejemplo, `"?search=keyword"`. Puedes acceder a esta cadena en la función de manejo de ruta utilizando args.query.

- #### request:
  Aquí se almacena el método HTTP de la solicitud, como `GET, POST, PUT, etc.` Puedes acceder a este valor en la función de manejo de ruta utilizando args.request.

  #### Contiene lo siguiente:
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
  Esta es una referencia a la sesión del cliente. La sesión es un mecanismo para almacenar datos entre solicitudes HTTP.
  Puedes acceder a los valores de la sesión utilizando `args.session["<VALOR>"]`, donde <VALOR> es la clave de datos que deseas recuperar o modificar de la sesión.
  Tambien contiene `Session.destroySession()` y `session.createSession()`


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

La clase UsersDB es una implementación de una base de datos SQLite diseñada para manejar información relacionada con usuarios. 
### Constructor UsersDB

```cpp
UsersDB(std::string file, bool create)
```
- Descripción: Este es el constructor de la clase UsersDB. Se utiliza para crear una instancia de la base de datos SQLite o abrir una existente. Puede especificar el archivo de la base de datos y si desea crearlo si no existe.
- Parámetros:
        file: El nombre del archivo de la base de datos SQLite.
        create: Un indicador booleano que especifica si se debe crear la base de datos si no existe.

#### Función getUsersName

```cpp
std::vector<std::string> getUsersName()
```
- Descripción: Esta función recupera los nombres de usuario almacenados en la base de datos.
- Retorno: Un vector de cadenas que contiene los nombres de usuario.

#### Función insertUser

```cpp
void insertUser(const std::string &User)
````
- Descripción: Inserta un nuevo usuario en la base de datos.
- Parámetros:

Función modifyUser

```cpp
void modifyUser(const std::string &User, const std::unordered_map<std::string, std::string> &data)
```
- Descripción: Modifica los datos de un usuario existente en la base de datos.
- Parámetros:
        User: El nombre del usuario que se va a modificar.
        data: Un mapa que contiene los datos que se actualizarán para el usuario.
- Uso:

```cpp
    std::unordered_map<std::string, std::string> userData;
    userData["campo1"] = "nuevo_valor";
    userData["campo2"] = "otro_nuevo_valor";
    database.modifyUser("UsuarioExistente", userData);
```

Función deleteUser

```cpp
void deleteUser(const std::string &User)
```

### Operador [] UsersDB

Se puede utilizar el operador `[]` para obtener o modificar una tabla de la base de datos, ademas de la tabla `'Users'`. La cual permite operar de la siguiente forma:
- ``` int countRows()```;
- ``` vector<string> getFields();```
- ``` unordered_map<string, string> getByID(const string &idValue);```
- ``` vector<string> getByField(const string &fieldName, const string &fieldValue);```
- ``` unordered_map<string, string> getoneByField(const string &idColumnName, const string &idValue);```
- ``` void insertRow(const unordered_map<string, string> &data);```
- ``` void updateRow(const string &id, const unordered_map<string, string> &data);```
- ``` void deleteByID(const string &idValue);```

### Otros Métodos

La clase UsersDB también incluye otros métodos útiles, como getFields, getUser, insertUsers, entre otros.
