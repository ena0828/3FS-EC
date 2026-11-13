# One backend is selected for the complete native artifact. Use separate source
# worktrees/target directories for independent scalar and ISA-L builds.
if (NOT DEFINED HF3FS_EC_BACKEND)
    set(HF3FS_EC_BACKEND "scalar")
endif ()
set(HF3FS_EC_BACKEND "${HF3FS_EC_BACKEND}" CACHE STRING "Native EC arithmetic backend: scalar or isal")
set_property(CACHE HF3FS_EC_BACKEND PROPERTY STRINGS scalar isal)
set(HF3FS_EC_ISAL_ROOT "${HF3FS_EC_ISAL_ROOT}" CACHE PATH "Optional private ISA-L prefix (no system fallback)")

if (NOT HF3FS_EC_BACKEND STREQUAL "scalar" AND NOT HF3FS_EC_BACKEND STREQUAL "isal")
    message(FATAL_ERROR "HF3FS_EC_BACKEND must be exactly scalar or isal")
endif ()

# These are ordinary configuration values, never a reusable find_library cache.
# Reset them on every include so changing the backend cannot retain an old link.
set(HF3FS_EC_ISAL_LIBRARY "")
set(HF3FS_EC_ISAL_LIBDIR "")
set(HF3FS_EC_ISAL_SHA256 "")

function(hf3fs_resolve_ec_isal)
    if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
        NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$" OR
        NOT CMAKE_SIZEOF_VOID_P EQUAL 8 OR CMAKE_CROSSCOMPILING)
        message(FATAL_ERROR "The native ISA-L backend currently requires native Linux x86-64")
    endif ()

    # Rust's #[link(name = "isal")] needs the development linker name. Reject a
    # static archive or linker script instead of silently selecting another ABI.
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".so")
    unset(_hf3fs_ec_isal_found)
    unset(_hf3fs_ec_isal_found CACHE)
    set(_private_root "")
    if (NOT HF3FS_EC_ISAL_ROOT STREQUAL "")
        if (NOT IS_ABSOLUTE "${HF3FS_EC_ISAL_ROOT}" OR
            NOT IS_DIRECTORY "${HF3FS_EC_ISAL_ROOT}" OR
            HF3FS_EC_ISAL_ROOT MATCHES "[;\r\n]")
            message(FATAL_ERROR "HF3FS_EC_ISAL_ROOT must be an existing absolute prefix without list/control separators")
        endif ()
        get_filename_component(_private_root "${HF3FS_EC_ISAL_ROOT}" REALPATH)
        set(_dirs "${_private_root}/lib" "${_private_root}/lib64"
                  "${_private_root}/usr/lib" "${_private_root}/usr/lib64")
        if (CMAKE_LIBRARY_ARCHITECTURE)
            list(APPEND _dirs "${_private_root}/lib/${CMAKE_LIBRARY_ARCHITECTURE}"
                              "${_private_root}/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}")
        endif ()
        # The explicitly supported platform also covers extracted distro packages
        # when a compiler has not populated CMAKE_LIBRARY_ARCHITECTURE.
        list(APPEND _dirs "${_private_root}/lib/x86_64-linux-gnu"
                          "${_private_root}/usr/lib/x86_64-linux-gnu")
        find_library(_hf3fs_ec_isal_found NAMES isal PATHS ${_dirs}
                     NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)
    else ()
        find_library(_hf3fs_ec_isal_found NAMES isal NO_CMAKE_FIND_ROOT_PATH)
    endif ()
    if (NOT _hf3fs_ec_isal_found)
        message(FATAL_ERROR "HF3FS_EC_BACKEND=isal requires a dynamic libisal.so development library in the selected prefix/search path")
    endif ()

    get_filename_component(_library "${_hf3fs_ec_isal_found}" REALPATH)
    get_filename_component(_libdir "${_hf3fs_ec_isal_found}" DIRECTORY)
    get_filename_component(_libdir "${_libdir}" REALPATH)
    unset(_hf3fs_ec_isal_found CACHE)
    if (_library MATCHES "[;\r\n]" OR _libdir MATCHES "[;\r\n]" OR
        NOT EXISTS "${_library}" OR IS_DIRECTORY "${_library}")
        message(FATAL_ERROR "ISA-L provider must be a regular dynamic library with a representable path")
    endif ()
    if (NOT _private_root STREQUAL "")
        foreach (_path IN ITEMS "${_library}" "${_libdir}")
            file(RELATIVE_PATH _relative "${_private_root}" "${_path}")
            if (IS_ABSOLUTE "${_relative}" OR _relative MATCHES "^[.][.](/|$)")
                message(FATAL_ERROR "ISA-L provider resolves outside HF3FS_EC_ISAL_ROOT")
            endif ()
        endforeach ()
    endif ()
    get_filename_component(_rust_library "${_libdir}/libisal.so" REALPATH)
    if (NOT EXISTS "${_libdir}/libisal.so" OR NOT _rust_library STREQUAL _library)
        message(FATAL_ERROR "Rust libisal.so and the C++ ISA-L provider must resolve to the same file")
    endif ()

    # This checks ELF class/type/machine, not symbols or runtime loader behavior.
    # The native integration probe must still exercise the linked implementation.
    file(READ "${_library}" _elf LIMIT 20 HEX)
    string(LENGTH "${_elf}" _elf_length)
    if (NOT _elf_length EQUAL 40 OR NOT _elf MATCHES "^7f454c460201")
        message(FATAL_ERROR "ISA-L provider is not a little-endian ELF64 library")
    endif ()
    string(SUBSTRING "${_elf}" 32 4 _elf_type)
    string(SUBSTRING "${_elf}" 36 4 _elf_machine)
    if (NOT _elf_type STREQUAL "0300" OR NOT _elf_machine STREQUAL "3e00")
        message(FATAL_ERROR "ISA-L provider must be an x86-64 ELF shared object")
    endif ()
    file(SHA256 "${_library}" _sha256)
    set(HF3FS_EC_ISAL_LIBRARY "${_library}" PARENT_SCOPE)
    set(HF3FS_EC_ISAL_LIBDIR "${_libdir}" PARENT_SCOPE)
    set(HF3FS_EC_ISAL_SHA256 "${_sha256}" PARENT_SCOPE)
    message(STATUS "EC backend: isal; provider=${_library}; SHA256=${_sha256}")
endfunction()

if (HF3FS_EC_BACKEND STREQUAL "isal")
    hf3fs_resolve_ec_isal()
else ()
    message(STATUS "EC backend: scalar")
endif ()
