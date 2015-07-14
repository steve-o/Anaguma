# CMake build script for UPA interactive provider
# x64 Windows Server-only
# 2013/02/07 -- Steven.McCoy@thomsonreuters.com

cmake_minimum_required (VERSION 2.8.8)

project (Anaguma)

# Thomson Reuters Robust Foundation API
set(UPA_ROOT D:/upa7.5.0.L1.win.rrg)
set(UPA_INCLUDE_DIRS
	${UPA_ROOT}/Include
)
set(UPA_LIBRARY_DIR ${UPA_ROOT}/Libs/WIN_64_VS100/Debug_MDd)
set(UPA_LIBRARY_DIRS ${UPA_LIBRARY_DIR})
set(UPA_LIBRARIES
	librsslData
	librsslMessages
	librsslTransport
)

# Boost headers plus built libraries
set(BOOST_ROOT D:/boost_1_54_0)
set(BOOST_LIBRARYDIR ${BOOST_ROOT}/stage/lib)
set(Boost_USE_STATIC_LIBS ON)
find_package (Boost 1.50 COMPONENTS atomic chrono thread REQUIRED)

#-----------------------------------------------------------------------------
# force off-tree build

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
message(FATAL_ERROR "CMake generation is not allowed within the source directory!
Remove the CMakeCache.txt file and try again from another folder, e.g.:

   del CMakeCache.txt
   mkdir build
   cd build
   cmake ..
")
endif(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})

#-----------------------------------------------------------------------------
# default to Release build

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING
      "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
endif(NOT CMAKE_BUILD_TYPE)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH  ${CMAKE_BINARY_DIR}/lib)

#-----------------------------------------------------------------------------
# platform specifics

add_definitions(
	-DWIN32
	-DWIN32_LEAN_AND_MEAN
# Windows Server 2008 R2
	-D_WIN32_WINNT=0x0601
# UPA version
        -DUPA_LIBRARY_VERSION="7.5.0."
)

# Parallel make.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")

# Optimization flags.
# http://msdn.microsoft.com/en-us/magazine/cc301698.aspx
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /GL")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /LTCG")
set(CMAKE_MODULE_LINKER_FLAGS_RELEASE "${CMAKE_MODULE_LINKER_FLAGS_RELEASE} /LTCG")

# Disable buffer security check.
# http://msdn.microsoft.com/en-us/library/8dbf701c(v=vs.80).aspx
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /GS-")

#-----------------------------------------------------------------------------
# source files

set(cxx-sources
	src/client.cc
	src/config.cc
	src/main.cc
	src/anaguma.cc
	src/provider.cc
	src/upa.cc
	src/upaostream.cc
	src/chromium/chromium_switches.cc
	src/chromium/command_line.cc
	src/chromium/debug/stack_trace.cc
	src/chromium/debug/stack_trace_win.cc
	src/chromium/memory/singleton.cc
	src/chromium/logging.cc
	src/chromium/string_piece.cc
	src/chromium/string_split.cc
	src/chromium/string_util.cc
	src/chromium/synchronization/lock.cc
	src/chromium/synchronization/lock_impl_win.cc
	src/chromium/vlog.cc
	src/googleurl/url_parse.cc
)

include_directories(
	include
	${CMAKE_CURRENT_BINARY_DIR}
	${UPA_INCLUDE_DIRS}
	${Boost_INCLUDE_DIRS}
)

link_directories(
	${UPA_LIBRARY_DIRS}
	${Boost_LIBRARY_DIRS}
)

#-----------------------------------------------------------------------------
# output

add_executable(Anaguma ${cxx-sources})

target_link_libraries(Anaguma
	${UPA_LIBRARIES}
	${Boost_LIBRARIES}
	ws2_32.lib
	wininet.lib
	dbghelp.lib	
)

# end of file
