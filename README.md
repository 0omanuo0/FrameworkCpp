# FramworkCpp
 
La librería `HttpServer` es una herramienta que te permite crear y configurar un servidor HTTP con capacidad para manejar solicitudes SSL. Aquí tienes una descripción de las principales funciones y clases disponibles en esta librería:

## Clase HttpServer

La clase `HttpServer` es el componente principal de la librería y se utiliza para configurar y gestionar un servidor HTTP.

### Constructor

```cpp
HttpServer(int port_server, const string SSLcontext_server[], char *host = "0.0.0.0", int max_connections = 10);
Claro, aquí tienes una documentación en formato de archivo de texto (TXT) para la librería que has proporcionado:

csharp

# Documentación de la Librería HttpServer

La librería `HttpServer` es una herramienta que te permite crear y configurar un servidor HTTP con capacidad para manejar solicitudes SSL. Aquí tienes una descripción de las principales funciones y clases disponibles en esta librería:

## Clase HttpServer

La clase `HttpServer` es el componente principal de la librería y se utiliza para configurar y gestionar un servidor HTTP.

### Constructor

```cpp
HttpServer(int port_server, const string SSLcontext_server[], char *host = "0.0.0.0", int max_connections = 10);

Este constructor se utiliza para crear una instancia de HttpServer especificando el puerto del servidor, el contexto SSL y otras opciones como el host y el número máximo de conexiones.
Iniciar el Servidor