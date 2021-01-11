cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)
project(csn)

option(BUILD_PATCHDD "build patchdd utility" OFF)

set(CMAKE_C_VISIBILITY_PRESET hidden)
if(POLICY CMP0063)
  cmake_policy(SET CMP0063 NEW)
endif()

include(CTest)

find_package(PkgConfig REQUIRED)
pkg_search_module(ZSTD REQUIRED libzstd)
pkg_search_module(CURL REQUIRED libcurl)
pkg_search_module(CRYPTO REQUIRED libcrypto)

add_compile_options(
	-Wall
	-Wextra
	-Wshadow
	-Wno-unused-parameter
	-Wmissing-noreturn
	-Wmissing-prototypes
	-Wstrict-prototypes
)

add_executable(csn
	log.c
	utils.c
	chunk.c
	chunker.c
	caibx.c
	sha.c
	store.c
	store-local.c
	store-http.c
	index.c
	target.c
	ui.c
	main.c
)
target_link_libraries(csn ${ZSTD_LIBRARIES} ${CURL_LIBRARIES} ${CRYPTO_LIBRARIES})
target_include_directories(csn PRIVATE ${ZSTD_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS} ${CRYPTO_INCLUDE_DIRS})

install(TARGETS csn RUNTIME DESTINATION bin)

if(BUILD_PATCHDD)
	add_executable(patchdd
	               log.c
	               utils.c
	               ui.c
	               patchdd.c
	)

	install(TARGETS patchdd RUNTIME DESTINATION bin)
endif()

if(BUILD_TESTING)
	add_subdirectory(test)
endif()
