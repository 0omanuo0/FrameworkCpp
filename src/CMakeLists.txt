# Recopila los archivos fuente de la librería
file(GLOB LIB_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp jinjaTemplating/*.cpp tools/*.cpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Define la biblioteca (estática o dinámica)
add_library(httpserver_lib STATIC ${LIB_SOURCES})

# Incluir directorios
include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/jinjaTemplating ${CMAKE_SOURCE_DIR}/tools)

# Añadir subdirectorio de my_expr
add_subdirectory(jinjaTemplating/my_expr)



# Busca libuv (ya instalado)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED libuv)

# Añade los directorios de encabezados de libuv
include_directories(${LIBUV_INCLUDE_DIRS})

# Añade uvw como subdirectorio
add_subdirectory(uvw)

# Linkea la biblioteca externa requerida
target_link_libraries(httpserver_lib my_expr_lib sqlite3 curl stdc++fs dl uvw z crypto)

# Opciones de compilación para la librería
target_compile_options(httpserver_lib PRIVATE
    $<$<CONFIG:Debug>: -g -Og -O0 -DDEBUG  -ggdb> # -Wall -Wextra -Wpedantic
    $<$<CONFIG:Release>:-O3 -g>
)

# Incluye directorios de cabeceras
target_include_directories(httpserver_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
