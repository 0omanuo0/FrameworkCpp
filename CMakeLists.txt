cmake_minimum_required(VERSION 3.10)

project(HttpServer)

# Set C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Source and binary directories
set(SRC_DIR src)
set(JINJA_DIR ${SRC_DIR}/jinjaTemplating)
set(UTILS_DIR ${SRC_DIR}/tools)
set(BIN_DIR ${CMAKE_SOURCE_DIR}/bin)

# Common CXX flags
include_directories(${SRC_DIR} ${JINJA_DIR} ${UTILS_DIR})

# Source files
file(GLOB SRCS ${SRC_DIR}/*.cpp ${JINJA_DIR}/*.cpp ${UTILS_DIR}/*.cpp)

# Output executable name
set(EXECUTABLE httpserver)

# Compiler flags
set(DEBUG_CXXFLAGS "-Wall -g -Og -fdiagnostics-color=always")
set(RELEASE_CXXFLAGS "-O3")

# Create binary directory if it doesn't exist
file(MAKE_DIRECTORY ${BIN_DIR})

# Define executable target
add_executable(${EXECUTABLE} ${SRCS} app.cpp)

# Set the output directory for the executable
set_target_properties(${EXECUTABLE} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR}
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${BIN_DIR}
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${BIN_DIR}
)

# Link libraries
target_link_libraries(${EXECUTABLE} ssl crypto sqlite3 curl)

# Debug configuration
set_target_properties(${EXECUTABLE} PROPERTIES COMPILE_FLAGS_DEBUG ${DEBUG_CXXFLAGS})

# Release configuration
set_target_properties(${EXECUTABLE} PROPERTIES COMPILE_FLAGS_RELEASE ${RELEASE_CXXFLAGS})

# Clean target
add_custom_target(clean_all
    COMMAND ${CMAKE_COMMAND} -E remove -f ${BIN_DIR}/*.o ${BIN_DIR}/${EXECUTABLE}
    COMMENT "Cleaning up..."
)