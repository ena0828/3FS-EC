if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CARGO_CMD cargo build)
    set(TARGET_DIR "debug")
else ()
    set(CARGO_CMD cargo build --release)
    set(TARGET_DIR "release")
endif ()

add_custom_target(cargo_build_all ALL)

macro(add_crate NAME)
    set(LIBRARY "${PROJECT_SOURCE_DIR}/target/${TARGET_DIR}/lib${NAME}.a")
    set(SOURCES
        "${PROJECT_SOURCE_DIR}/target/cxxbridge/${NAME}/src/cxx.rs.h"
        "${PROJECT_SOURCE_DIR}/target/cxxbridge/${NAME}/src/cxx.rs.cc"
    )

    # Keep workspace defaults and crate verification inside the same edge.
    # This edge owns every generated file consumed by C++ compilation/linking.
    add_custom_target(
        cargo_build_${NAME}
        COMMAND ${CMAKE_COMMAND} -E chdir "${PROJECT_SOURCE_DIR}" ${CARGO_CMD}
        COMMAND ${CARGO_CMD}
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/${NAME}"
        BYPRODUCTS ${SOURCES} ${LIBRARY}
        VERBATIM
    )
    add_dependencies(cargo_build_all cargo_build_${NAME})

    add_library(${NAME} STATIC ${SOURCES} ${LIBRARY})
    target_link_libraries(${NAME} pthread dl ${LIBRARY})
    target_include_directories(${NAME} PUBLIC "${PROJECT_SOURCE_DIR}/target/cxxbridge")
    target_compile_options(${NAME} PUBLIC -Wno-dollar-in-identifier-extension)
    add_dependencies(${NAME} cargo_build_${NAME})
endmacro()
