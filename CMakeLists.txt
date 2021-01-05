cmake_minimum_required(VERSION 3.12)

project(xi)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CheckCXXCompilerFlag)
include(CheckIncludeFile)

check_cxx_compiler_flag("-pg" has_gprof "int main() { return 0; }")
if (CMAKE_PROFILE AND has_gprof)
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg")
endif()

# check for the C thread support library
find_package(Threads REQUIRED)
check_include_file("threads.h" have_threads_h)
set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})
check_c_source_compiles("#include <threads.h>
int main() { thrd_t t; thrd_create(&t, &main, NULL); }" has_thread_support)
check_c_source_compiles("#include <time.h>
int main() { struct timespec ts; timespec_get(&ts, 0); }" has_timespec_get)

if(NOT has_thread_support)
include_directories(src/compat)
endif()
if(CMAKE_USE_PTHREADS_INIT)
add_definitions(-DHAVE_PTHREAD)
if(has_timespec_get)
add_definitions(-DHAVE_TIMESPEC_GET)
endif()
endif()

include_directories(src)
add_executable(xi src/xi.cc src/xi_nub.cc)
target_link_libraries(xi ${CMAKE_THREAD_LIBS_INIT})

add_executable(test_sem tests/test_sem.cc src/xi_nub.cc)
target_link_libraries(test_sem ${CMAKE_THREAD_LIBS_INIT})
add_test(test_sem test_sem)

add_executable(test_exe tests/test_exe.cc)
target_link_libraries(test_exe ${CMAKE_THREAD_LIBS_INIT})
add_test(test_exe test_exe)

if (WIN32)
set_source_files_properties(src/xi.cc src/xi_nub.cc
	PROPERTIES COMPILE_DEFINITIONS _CRT_SECURE_NO_WARNINGS
)
endif ()
