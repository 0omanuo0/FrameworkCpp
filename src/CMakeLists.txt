# Recopila los archivos fuente de la librería
file(GLOB LIB_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp jinjaTemplating/*.cpp tools/*.cpp)

# Define la biblioteca (estática o dinámica)
add_library(httpserver_lib STATIC ${LIB_SOURCES})

# Incluir directorios
include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/jinjaTemplating ${CMAKE_SOURCE_DIR}/tools)

# Añadir subdirectorio de my_expr
add_subdirectory(jinjaTemplating/my_expr)

# Linkea la biblioteca externa requerida
target_link_libraries(httpserver_lib my_expr_lib ssl crypto sqlite3 curl stdc++fs dl)

# Opciones de compilación para la librería
target_compile_options(httpserver_lib PRIVATE
    $<$<CONFIG:Debug>:-Wall -g -Og -O0 -DDEBUG>
    $<$<CONFIG:Release>:-O3>
)

# Incluye directorios de cabeceras
target_include_directories(httpserver_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
