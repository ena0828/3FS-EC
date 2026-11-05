find_path(ISAL_INCLUDE_DIR NAMES isa-l/erasure_code.h)
find_library(ISAL_LIBRARY NAMES isal)
if(NOT ISAL_INCLUDE_DIR OR NOT ISAL_LIBRARY)
  message(FATAL_ERROR "erasure_codec requires Intel ISA-L headers (isa-l/erasure_code.h) and libisal")
endif()

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(ISAL QUIET libisal)
endif()
message(STATUS "erasure_codec ISA-L: include=${ISAL_INCLUDE_DIR}, library=${ISAL_LIBRARY}, version=${ISAL_VERSION}")

add_library(erasure_codec STATIC ErasureCodec.cc ErasureCodec.h)
target_include_directories(erasure_codec PUBLIC ${PROJECT_SOURCE_DIR}/src PRIVATE ${ISAL_INCLUDE_DIR})
target_link_libraries(erasure_codec PUBLIC ${ISAL_LIBRARY})

add_library(ec_layout STATIC ECLayout.cc ECLayout.h)
target_include_directories(ec_layout PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ec_layout PUBLIC erasure_codec)
