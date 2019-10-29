cmake_minimum_required(VERSION 2.8)

file(GLOB COMMON_SRC "*.cpp")
file(GLOB COMMON_HEADERS "*.hpp")

message(STATUS "Creating common lib")

add_library(common STATIC ${COMMON_SRC})
target_link_libraries(common)