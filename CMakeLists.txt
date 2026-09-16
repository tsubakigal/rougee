cmake_minimum_required(VERSION 3.23)

project(rougee)
set(CMAKE_CXX_STANDARD 23)

add_library(detours STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/Detours/src/creatwth.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Detours/src/detours.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Detours/src/disasm.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Detours/src/image.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Detours/src/modules.cpp
)
target_include_directories(detours PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/Detours/src
)

add_executable(rougee)

target_sources(rougee PRIVATE rougee.cpp)
target_include_directories(rougee PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Detours/src)
target_link_libraries(rougee PRIVATE
    detours
)
add_library(rougee_dll SHARED rougeedll.cpp tp_stub.cpp)
target_include_directories(rougee_dll PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/Detours/src
)
set_target_properties(rougee_dll PROPERTIES
    OUTPUT_NAME "rougee"
)
target_link_libraries(rougee_dll PRIVATE
    detours
)
