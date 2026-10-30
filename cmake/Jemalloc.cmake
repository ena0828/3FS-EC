add_library(jemalloc INTERFACE)
add_library(hf3fs_jemalloc_shared SHARED IMPORTED)

include(ExternalProject)
set(JEMALLOC_DIR "${CMAKE_BINARY_DIR}/third_party/jemalloc")
set(HF3FS_EXTERNAL_BUILD_JOBS "6" CACHE STRING "Parallel jobs for external Make builds")
if(NOT HF3FS_EXTERNAL_BUILD_JOBS MATCHES "^[1-9][0-9]*$")
  message(FATAL_ERROR "HF3FS_EXTERNAL_BUILD_JOBS must be a positive integer")
endif()

ExternalProject_add(Hf3fsJemalloc_project
  SOURCE_DIR "${PROJECT_SOURCE_DIR}/third_party/jemalloc"
  BUILD_BYPRODUCTS "${JEMALLOC_DIR}/include/jemalloc/jemalloc.h"
  "${JEMALLOC_DIR}/lib/libjemalloc.so.2"
  CONFIGURE_COMMAND ./autogen.sh && ./configure --prefix=${JEMALLOC_DIR} --disable-cxx --enable-prof --disable-initial-exec-tls
  BUILD_IN_SOURCE ON
  BUILD_COMMAND make -j ${HF3FS_EXTERNAL_BUILD_JOBS}
  INSTALL_DIR "${JEMALLOC_DIR}"
  INSTALL_COMMAND make install)

add_dependencies(hf3fs_jemalloc_shared Hf3fsJemalloc_project)
set_target_properties(hf3fs_jemalloc_shared PROPERTIES IMPORTED_LOCATION "${JEMALLOC_DIR}/lib/libjemalloc.so.2")
target_include_directories(hf3fs_jemalloc_shared INTERFACE "${JEMALLOC_DIR}/include")
target_link_libraries(jemalloc INTERFACE hf3fs_jemalloc_shared)
