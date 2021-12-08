# - Find Babeltrace
# This module accepts the following optional variables:
#    Babeltrace_PATH_HINT   = A hint on BABELTRACE install path.
#
# This module defines the following variables:
#    Babeltrace_FOUND       = Was Babeltrace found or not?
#    Babeltrace_EXECUTABLE  = The path to lttng command
#    Babeltrace_LIBRARIES   = The list of libraries to link to when using Babeltrace
#    Babeltrace_INCLUDE_DIR = The path to Babeltrace include directory
#
# On can set Babeltrace_PATH_HINT before using find_package(Babeltrace) and the
# module with use the PATH as a hint to find Babeltrace.
#
# The hint can be given on the command line too:
#   cmake -DBabeltrace_PATH_HINT=/DATA/ERIC/Babeltrace /path/to/source

if(Babeltrace_PATH_HINT)
  message(STATUS "FindBabeltrace: using PATH HINT: ${Babeltrace_PATH_HINT}")
else()
  set(Babeltrace_PATH_HINT)
endif()

#One can add his/her own builtin PATH.
#FILE(TO_CMAKE_PATH "/DATA/ERIC/Babeltrace" MYPATH)
#list(APPEND Babeltrace_PATH_HINT ${MYPATH})

find_path(Babeltrace_INCLUDE_DIR
          NAMES babeltrace/babeltrace.h babeltrace/ctf/events.h babeltrace/ctf/iterator.h
          PATHS ${Babeltrace_PATH_HINT}
          PATH_SUFFIXES include
          DOC "The Babeltrace include headers")

find_path(Babeltrace_LIBRARY_DIR
          NAMES libbabeltrace.so
          NAMES libbabeltrace-ctf.so
          PATHS ${Babeltrace_PATH_HINT}
          PATH_SUFFIXES lib lib64
          DOC "The Babeltrace libraries")

find_library(BABELTRACE NAMES babeltrace PATHS ${Babeltrace_LIBRARY_DIR})
find_library(Babeltrace_CTF NAMES babeltrace-ctf PATHS ${Babeltrace_LIBRARY_DIR})

set(Babeltrace_LIBRARIES ${BABELTRACE} ${Babeltrace_CTF})

message(STATUS "Looking for Babeltrace...")
set(Babeltrace_NAMES "babeltrace;babeltrace-ctf")
# FIND_PROGRAM twice using NO_DEFAULT_PATH on first shot
find_program(Babeltrace_EXECUTABLE
  NAMES ${Babeltrace_NAMES}
  PATHS ${Babeltrace_PATH_HINT}/bin /bin
  NO_DEFAULT_PATH
  DOC "The BABELTRACE command line tool")

# handle the QUIETLY and REQUIRED arguments and set PRELUDE_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Babeltrace
                                  REQUIRED_VARS Babeltrace_INCLUDE_DIR Babeltrace_LIBRARY_DIR)
# VERSION FPHSA options not handled by CMake version < 2.8.2)
#                                  VERSION_VAR)
mark_as_advanced(Babeltrace_INCLUDE_DIR)
mark_as_advanced(Babeltrace_LIBRARY_DIR)
