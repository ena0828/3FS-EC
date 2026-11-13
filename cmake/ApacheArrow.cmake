add_library(apache_arrow_static INTERFACE)
add_library(arrow_static STATIC IMPORTED)
add_library(parquet_static STATIC IMPORTED)
add_library(arrow_dependencies STATIC IMPORTED)

set(PREFIX "${CMAKE_CURRENT_BINARY_DIR}")
set(ARROW_RELEASE_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/src/apache-arrow-cpp/cpp/build/release")

# https://cmake.org/cmake/help/latest/policy/CMP0097.html
# Starting with CMake 3.16, explicitly setting GIT_SUBMODULES to an empty string
# means no submodules will be initialized or updated.
cmake_policy(SET CMP0097 NEW)

if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.28)
    set(ARROW_BUILD_PARALLEL "")
else()
    set(ARROW_BUILD_PARALLEL "-j8")
endif()

include(ExternalProject)
set(HF3FS_ARROW_SOURCE_DIR "" CACHE PATH "Explicit preverified Arrow source snapshot (no download/update)")
# Common nonempty options may expand as a list. Empty ExternalProject commands
# and GIT_SUBMODULES must be literal quoted arguments at the actual call site.
set(ARROW_COMMON_ARGS
    PREFIX ${PREFIX}
    SOURCE_SUBDIR "cpp"
    BUILD_IN_SOURCE ON
    INSTALL_DIR ${PREFIX}
    # Arrow resolves only enabled dependencies and checks their pinned URL_HASH.
    # Do not prefetch all optional packages or source a possibly partial export.sh.
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -S . -B .
        -DCMAKE_BUILD_TYPE=Release
        -DARROW_USE_CCACHE=OFF
        -DARROW_USE_SCCACHE=OFF
        -DARROW_DEPENDENCY_SOURCE=BUNDLED
        -DARROW_BUILD_STATIC=ON
        -DARROW_JEMALLOC=ON
        -DARROW_SIMD_LEVEL=DEFAULT
        -DARROW_BUILD_EXAMPLES=OFF
        -DARROW_PARQUET=ON -DARROW_CSV=ON
        -DARROW_WITH_ZSTD=ON -DARROW_WITH_LZ4=ON -DARROW_WITH_ZLIB=ON
    BUILD_COMMAND ${CMAKE_COMMAND} --build . ${ARROW_BUILD_PARALLEL}
    BUILD_JOB_SERVER_AWARE 1
    INSTALL_COMMAND cmake --install . --prefix "${PREFIX}"
    BUILD_BYPRODUCTS
        "${ARROW_RELEASE_BUILD_DIR}/libarrow.a"
        "${ARROW_RELEASE_BUILD_DIR}/libparquet.a"
        "${ARROW_RELEASE_BUILD_DIR}/libarrow_bundled_dependencies.a"
)
if(HF3FS_ARROW_SOURCE_DIR)
    if(NOT IS_ABSOLUTE "${HF3FS_ARROW_SOURCE_DIR}" OR
       NOT HF3FS_ARROW_SOURCE_DIR STREQUAL "${PREFIX}/src/apache-arrow-cpp" OR
       NOT EXISTS "${HF3FS_ARROW_SOURCE_DIR}/.git" OR
       NOT EXISTS "${HF3FS_ARROW_SOURCE_DIR}/cpp/CMakeLists.txt")
        message(FATAL_ERROR "Arrow prepared source must be the verified fresh build/src/apache-arrow-cpp")
    endif()
    ExternalProject_Add(apache-arrow-cpp ${ARROW_COMMON_ARGS}
        SOURCE_DIR "${HF3FS_ARROW_SOURCE_DIR}"
        DOWNLOAD_COMMAND ""
        UPDATE_COMMAND ""
        GIT_SUBMODULES "")
else()
    ExternalProject_Add(apache-arrow-cpp ${ARROW_COMMON_ARGS}
        GIT_REPOSITORY https://github.com/apache/arrow.git
        GIT_TAG b7d2f7ffca66c868bd2fce5b3749c6caa002a7f0
        GIT_SHALLOW ON
        GIT_PROGRESS ON
        GIT_SUBMODULES "")
endif()

add_dependencies(arrow_static apache-arrow-cpp)
add_dependencies(parquet_static apache-arrow-cpp)
add_dependencies(arrow_dependencies apache-arrow-cpp)
set_target_properties(arrow_static PROPERTIES IMPORTED_LOCATION "${ARROW_RELEASE_BUILD_DIR}/libarrow.a")
set_target_properties(parquet_static PROPERTIES IMPORTED_LOCATION "${ARROW_RELEASE_BUILD_DIR}/libparquet.a")
set_target_properties(arrow_dependencies PROPERTIES IMPORTED_LOCATION "${ARROW_RELEASE_BUILD_DIR}/libarrow_bundled_dependencies.a")
target_include_directories(apache_arrow_static SYSTEM INTERFACE "${PREFIX}/include")
target_link_libraries(apache_arrow_static INTERFACE parquet_static arrow_static arrow_dependencies)
