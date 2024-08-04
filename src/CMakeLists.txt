# src/CMakeLists.txt

# Source files
file(GLOB SRCS *.cpp jinjaTemplating/*.cpp tools/*.cpp)

# Crear una biblioteca estática o compartida
add_library(httpserver_lib ${SRCS})

# Common CXX flags
include_directories(${SRC_DIR} ${SRC_DIR}/jinjaTemplating ${SRC_DIR}/tools)

# Define el ejecutable principal que usa la biblioteca
add_executable(httpserver ${CMAKE_SOURCE_DIR}/app.cpp)

# Linkear el ejecutable principal con la biblioteca
target_link_libraries(httpserver httpserver_lib ssl crypto sqlite3 curl stdc++fs)

# Set the output directory for the executable
set_target_properties(httpserver PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR}
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${BIN_DIR}
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${BIN_DIR}
)

# Compiler flags
set(DEBUG_CXXFLAGS "-Wall -g -Og -fdiagnostics-color=always")
set(RELEASE_CXXFLAGS "-O3")

# Debug configuration
set_target_properties(httpserver PROPERTIES COMPILE_FLAGS_DEBUG ${DEBUG_CXXFLAGS})

# Release configuration
set_target_properties(httpserver PROPERTIES COMPILE_FLAGS_RELEASE ${RELEASE_CXXFLAGS})
