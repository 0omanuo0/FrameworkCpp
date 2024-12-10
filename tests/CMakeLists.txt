# tests/CMakeLists.txt

enable_testing()

# Incluir los directorios de los archivos fuente
include_directories(${SRC_DIR} ${SRC_DIR}/jinjaTemplating ${SRC_DIR}/tools)

# Encontrar Google Test
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Añadir los ejecutables de test
file(GLOB TEST_SRCS ${TESTS_DIR}/*.cpp)

foreach(TEST_SRC ${TEST_SRCS})
    get_filename_component(TEST_NAME ${TEST_SRC} NAME_WE)
    add_executable(${TEST_NAME} ${TEST_SRC})

    # Enlazar los ejecutables de test con la librería del proyecto y Google Test -ldl
    target_link_libraries(${TEST_NAME} ${GTEST_LIBRARIES} pthread httpserver_lib ssl crypto sqlite3 curl stdc++fs dl)

    # Registrar los tests
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endforeach()
