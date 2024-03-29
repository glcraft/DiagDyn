cmake_minimum_required(VERSION 3.10)

project(DiagDyn)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PlatformTarget x64)
else()
    set(PlatformTarget x86)
endif()

file(GLOB SRC
    "*.cpp"
    "*.h"
)
add_executable(DiagDyn ${SRC})

set_target_properties(DiagDyn PROPERTIES 
    OUTPUT_NAME "DiagDyn_${PlatformTarget}"
    CXX_STANDARD 20
)
set(CompilerFlags
    CMAKE_CXX_FLAGS
    CMAKE_CXX_FLAGS_DEBUG
    CMAKE_CXX_FLAGS_RELEASE
    CMAKE_C_FLAGS
    CMAKE_C_FLAGS_DEBUG
    CMAKE_C_FLAGS_RELEASE
)
foreach(CompilerFlag ${CompilerFlags})
    string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()