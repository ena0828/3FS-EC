include("${CMAKE_CURRENT_LIST_DIR}/EcCodecBackend.cmake")

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CARGO_CMD cargo build --locked)
    set(TARGET_DIR "debug")
else ()
    set(CARGO_CMD cargo build --locked --release)
    set(TARGET_DIR "release")
endif ()

add_custom_target(cargo_build_all ALL)

macro(add_crate NAME)
    set(LIBRARY "${PROJECT_SOURCE_DIR}/target/${TARGET_DIR}/lib${NAME}.a")
    set(SOURCES
        "${PROJECT_SOURCE_DIR}/target/cxxbridge/${NAME}/src/cxx.rs.h"
        "${PROJECT_SOURCE_DIR}/target/cxxbridge/${NAME}/src/cxx.rs.cc"
    )
    # Reset per edge; scalar must not inherit feature flags or a private provider
    # from a previous configuration or the calling shell.
    set(_ec_workspace_features)
    set(_ec_crate_features)
    set(_ec_cargo_env "--unset=HF3FS_EC_ISAL_LIBDIR")
    if ("${NAME}" STREQUAL "chunk_engine" AND HF3FS_EC_BACKEND STREQUAL "isal")
        set(_ec_workspace_features --features chunk_engine/isal-backend)
        set(_ec_crate_features --features isal-backend)
        set(_ec_cargo_env "HF3FS_EC_ISAL_LIBDIR=${HF3FS_EC_ISAL_LIBDIR}")
    endif ()

    # Keep workspace defaults and crate verification inside the same edge.
    # This edge owns every generated file consumed by C++ compilation/linking.
    add_custom_target(
        cargo_build_${NAME}
        COMMAND ${CMAKE_COMMAND} -E chdir "${PROJECT_SOURCE_DIR}"
                ${CMAKE_COMMAND} -E env ${_ec_cargo_env} ${CARGO_CMD} ${_ec_workspace_features}
        COMMAND ${CMAKE_COMMAND} -E env ${_ec_cargo_env} ${CARGO_CMD} ${_ec_crate_features}
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/${NAME}"
        BYPRODUCTS ${SOURCES} ${LIBRARY}
        VERBATIM
    )
    add_dependencies(cargo_build_all cargo_build_${NAME})

    add_library(${NAME} STATIC ${SOURCES} ${LIBRARY})
    target_link_libraries(${NAME} pthread dl "${LIBRARY}")
    if ("${NAME}" STREQUAL "chunk_engine" AND HF3FS_EC_BACKEND STREQUAL "isal")
        target_link_libraries(${NAME} "${HF3FS_EC_ISAL_LIBRARY}")
    endif ()
    target_include_directories(${NAME} PUBLIC "${PROJECT_SOURCE_DIR}/target/cxxbridge")
    target_compile_options(${NAME} PUBLIC -Wno-dollar-in-identifier-extension)
    add_dependencies(${NAME} cargo_build_${NAME})
endmacro()
