cmake_minimum_required(VERSION 3.28)
project(ec_codec_bridge_probe LANGUAGES C CXX)

# Compile the actual AddCrate edge and generated CXX source. This does not mock
# the Rust FFI or build the full 3FS service dependency graph.
get_filename_component(EC_SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." REALPATH)
set(PROJECT_SOURCE_DIR "${EC_SOURCE_ROOT}")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
include("${EC_SOURCE_ROOT}/cmake/AddCrate.cmake")
add_subdirectory(crate)
add_executable(ec_codec_bridge_probe main.cc)
target_link_libraries(ec_codec_bridge_probe PRIVATE chunk_engine)
