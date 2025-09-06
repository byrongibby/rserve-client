###########################################################
## CMAKE SETUP
###########################################################

cmake_minimum_required(VERSION 3.10)
project(rserve-client)

###########################################################
## LIBRARY
###########################################################

add_library(rserve-client SHARED rserve.c rexp.c rlist.c)
add_library(rserve-client-static STATIC rserve.c rexp.c rlist.c)

###########################################################
## EXECUTABLES
###########################################################

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(rserve-demo ${CMAKE_CURRENT_SOURCE_DIR}/test/demo.c)
add_executable(rserve-test ${CMAKE_CURRENT_SOURCE_DIR}/test/test.c)
add_executable(rserve-ocap ${CMAKE_CURRENT_SOURCE_DIR}/test/ocap.c)

target_link_libraries(rserve-demo rserve-client)
target_link_libraries(rserve-test rserve-client)
target_link_libraries(rserve-ocap rserve-client)

###########################################################
## COMPILER FLAGS
###########################################################

target_compile_options(rserve-client PUBLIC -Wall -Wextra -Werror -std=c99 -g) # -O3 -Os
