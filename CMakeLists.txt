cmake_minimum_required(VERSION 2.8.13)
project(lttng_to_chrome)

if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to 'RelWithDebInfo' as none was specified.")
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Choose the type of build." FORCE)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)

find_package(Babeltrace REQUIRED)
include_directories(${BABELTRACE_INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wpedantic")

add_executable(lttng_to_chrome lttng_to_chrome.cpp)
target_link_libraries(lttng_to_chrome ${BABELTRACE_LIBRARIES})
