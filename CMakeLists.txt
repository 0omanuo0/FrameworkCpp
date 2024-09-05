cmake_minimum_required(VERSION 3.10)

project(HttpServer)

# Set C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Set CMake policies to avoid warnings
if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
    cmake_policy(SET CMP0012 NEW)
    cmake_policy(SET CMP0028 NEW)
endif(COMMAND cmake_policy)

# Source and binary directories
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(TESTS_DIR ${CMAKE_SOURCE_DIR}/tests)
set(BIN_DIR ${CMAKE_SOURCE_DIR}/bin)

# Create binary directory if it doesn't exist
file(MAKE_DIRECTORY ${BIN_DIR})

# Set default build type to Release if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build: Debug, Release, RelWithDebInfo, MinSizeRel" FORCE)
endif()

# Display build type
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Add Release and Debug specific flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Add subdirectories
add_subdirectory(${SRC_DIR})
add_subdirectory(${TESTS_DIR})

# Clean target
add_custom_target(clean_all
    COMMAND ${CMAKE_COMMAND} -E remove -f ${BIN_DIR}/*.o ${BIN_DIR}/httpserver
    COMMENT "Cleaning up..."
)
