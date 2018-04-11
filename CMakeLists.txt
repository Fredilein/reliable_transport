cmake_minimum_required(VERSION 3.8)
project(code)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        buffer.c
        buffer.h
        reliable.c
        reliable_blank_skeleton.c
        rlib.c
        rlib.h)

add_executable(code ${SOURCE_FILES})