# CMake build script for RFA interactive provider
# x64 Windows Server-only
# 2012/07/18 -- Steven.McCoy@thomsonreuters.com

cmake_minimum_required (VERSION 2.8.8)

project (Anaguma)

# Thomson Reuters Robust Foundation API
set(RFA_ROOT D:/rfa7.4.0.L1.win-shared.rrg)
set(RFA_INCLUDE_DIRS
	${RFA_ROOT}/Include
	${RFA_ROOT}/Include/rwf
)
set(RFA_LIBRARY_DIR ${RFA_ROOT}/Libs/WIN_64_VS100/Release_MD)
set(RFA_LIBRARY_DIRS ${RFA_LIBRARY_DIR})
set(RFA_LIBRARIES
	RFA7_Common100_x64.lib
	RFA7_Config100_x64.lib
	RFA7_Logger100_x64.lib
	RFA7_Data100_x64.lib
	RFA7_Connections100_x64.lib
	RFA7_Connections_OMM100_x64.lib
	RFA7_SessionLayer100_x64.lib
	DACS7_lock100_x64.lib
)

# Boost headers plus built libraries
set(BOOST_ROOT D:/boost_1_51_0)
set(BOOST_LIBRARYDIR ${BOOST_ROOT}/stage/lib)
set(Boost_USE_STATIC_LIBS ON)
find_package (Boost 1.50 COMPONENTS chrono thread REQUIRED)

# Boost Atomics
set(Boost_INCLUDE_DIRS
	"D:/boost.atomic"
	${Boost_INCLUDE_DIRS}
)

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
# RFA version
        -DRFA_LIBRARY_VERSION="7.4.0."
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
	src/error.cc
	src/main.cc
	src/anaguma.cc
	src/provider.cc
	src/rfa.cc
	src/rfa_logging.cc
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
	${RFA_INCLUDE_DIRS}
	${Boost_INCLUDE_DIRS}
)

link_directories(
	${RFA_LIBRARY_DIRS}
	${Boost_LIBRARY_DIRS}
)

#-----------------------------------------------------------------------------
# output

add_executable(Anaguma ${cxx-sources})

target_link_libraries(Anaguma
	${RFA_LIBRARIES}
	${Boost_LIBRARIES}
	ws2_32.lib
	dbghelp.lib
)

# end of file
