cmake_minimum_required(VERSION 3.5)
project(ctf2ctf VERSION 0.1)

function(check_submodule NAME SUBMODULE_PATH)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${SUBMODULE_PATH}" )
        if (EXISTS "${PROJECT_SOURCE_DIR}/.git")
            message(FATAL_ERROR
                "The ${NAME} git submodule is not initialized.\n"
                "Please run the following commands in the source directory (${PROJECT_SOURCE_DIR}):\n"
                "    git submodule update --init --recursive\n"
            )
        else()
            message(FATAL_ERROR
                "The ${NAME} submodule is missing - please report a broken source package.\n"
            )
        endif()
    endif()
endfunction()

check_submodule("args" "3rdparty/args/args.hxx")

if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to 'RelWithDebInfo' as none was specified.")
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Choose the type of build." FORCE)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)

find_package(Babeltrace REQUIRED)
find_package(QT NAMES Qt6 Qt5)
if (QT_FOUND)
    find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Gui REQUIRED)
    set(QtGui_FOUND ON)
endif()
include_directories(${Babeltrace_INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR} 3rdparty/)

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wpedantic")

configure_file(config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h @ONLY)
configure_file(ctf2ctf-gz.sh.in ${CMAKE_CURRENT_BINARY_DIR}/ctf2ctf-gz @ONLY)

add_executable(ctf2ctf ctf2ctf.cpp clioptions.cpp)
target_link_libraries(ctf2ctf ${Babeltrace_LIBRARIES} -lstdc++fs)

if (QT_FOUND)
    target_link_libraries(ctf2ctf Qt${QT_VERSION_MAJOR}::Gui)
endif()

include(GNUInstallDirs)
install(TARGETS ctf2ctf RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
