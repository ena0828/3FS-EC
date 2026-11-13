# add_crate resolves its crate directory relative to the production storage
# directory. Use exactly that existing convention, with no alternate crate.
set(CMAKE_CURRENT_SOURCE_DIR "${EC_SOURCE_ROOT}/src/storage")
add_crate(chunk_engine)
