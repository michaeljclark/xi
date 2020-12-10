cmake_minimum_required(VERSION 3.12)

project(xi)

include(CheckCXXCompilerFlag)

check_cxx_compiler_flag("-pg" has_gprof "int main() { return 0; }")
if (CMAKE_PROFILE AND has_gprof)
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src)
add_executable(xi src/xi.cc)
