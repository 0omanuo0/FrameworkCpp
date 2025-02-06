cmake_minimum_required(VERSION 3.10)
project(HttpServer)

# Establecer el estándar de C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Definir directorios
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
# set(BIN_DIR ${CMAKE_SOURCE_DIR}/bin)
set(TEST_DIR ${CMAKE_SOURCE_DIR}/tests)

# Crear directorio de salida si no existe
# file(MAKE_DIRECTORY ${BIN_DIR})

# Incluir subdirectorio de la librería
add_subdirectory(${SRC_DIR})

# Agregar el ejecutable principal
add_executable(httpserver ${CMAKE_SOURCE_DIR}/app.cpp)

# Incluir el directorio de cabeceras
target_include_directories(httpserver PUBLIC ${SRC_DIR})

# Linkear el ejecutable con la librería
target_link_libraries(httpserver httpserver_lib uv sqlite3 curl stdc++fs dl uvw z crypto)

# Incluir subdirectorio de tests
if (EXISTS ${TEST_DIR})
    enable_testing()
    add_subdirectory(${TEST_DIR})
endif()
