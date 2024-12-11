# Habilitar soporte para pruebas
enable_testing()

# Incluir los directorios de los archivos fuente necesarios
include_directories(
    ${SRC_DIR}
    ${SRC_DIR}/jinjaTemplating
    ${SRC_DIR}/tools
)

# Encontrar Google Test
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Buscar todos los archivos de prueba en el directorio actual
file(GLOB TEST_SOURCES ${TEST_DIR}/*.cpp)

# Iterar sobre cada archivo de prueba encontrado
foreach(TEST_SOURCE ${TEST_SOURCES})
    # Extraer el nombre del test (sin extensión) para usarlo como nombre del ejecutable
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)

    # Crear un ejecutable para cada archivo de prueba
    add_executable(${TEST_NAME} ${TEST_SOURCE})

    # Enlazar el ejecutable con las bibliotecas requeridas
    target_link_libraries(
        ${TEST_NAME}
        ${GTEST_LIBRARIES} 
        pthread 
        httpserver_lib
        my_expr_lib
        ssl 
        crypto 
        sqlite3 
        curl 
        stdc++fs 
        dl
    )

    # Registrar el ejecutable como una prueba
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endforeach()
