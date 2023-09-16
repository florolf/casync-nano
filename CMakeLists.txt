cmake_minimum_required(VERSION 3.1.0...3.5 FATAL_ERROR)
project(csn LANGUAGES C)

option(BUILD_PATCHDD "build patchdd utility" OFF)
option(BUILD_CSN_BENCH "build casync-nano benchmarking utility" OFF)
option(BUILD_CSN "build main casync tool" ON)

set(CMAKE_C_VISIBILITY_PRESET hidden)
if(POLICY CMP0063)
  cmake_policy(SET CMP0063 NEW)
endif()

add_compile_options(
	-Wall
	-Wextra
	-Wshadow
	-Wno-unused-parameter
	-Wmissing-noreturn
	-Wmissing-prototypes
	-Wstrict-prototypes
)

if(BUILD_CSN)
	include(CTest)

	find_package(PkgConfig REQUIRED)
	pkg_search_module(ZSTD REQUIRED libzstd)
	pkg_search_module(CURL REQUIRED libcurl)
	pkg_search_module(CRYPTO REQUIRED libcrypto)

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
	install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink csn \$ENV{DESTDIR}/\${CMAKE_INSTALL_PREFIX}/bin/casync)")

	if(BUILD_TESTING)
		add_subdirectory(test)
	endif()
endif()

if(BUILD_PATCHDD)
	add_executable(patchdd
	               log.c
	               utils.c
	               ui.c
	               patchdd.c
	)

	install(TARGETS patchdd RUNTIME DESTINATION bin)
endif()

if(BUILD_CSN_BENCH)
	add_executable(csn-bench
	               log.c
	               utils.c
	               sha.c
		       chunker.c
	               test/xorshift32.c
	               csn-bench.c
	)

	target_link_libraries(csn-bench ${CRYPTO_LIBRARIES})
	target_include_directories(csn-bench PRIVATE ${CRYPTO_INCLUDE_DIRS})

	install(TARGETS csn-bench RUNTIME DESTINATION bin)
endif()
