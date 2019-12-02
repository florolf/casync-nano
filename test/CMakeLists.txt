find_package(PkgConfig REQUIRED)

pkg_search_module(CMOCKA REQUIRED cmocka)

add_compile_options(
	-Wall
	-Wextra
	-Wshadow
	-Wno-unused-parameter
	-Wmissing-noreturn
	-Wmissing-prototypes
	-Wstrict-prototypes

	-fsanitize=undefined
	-fsanitize=address
)

link_libraries(-fsanitize=address -fsanitize=undefined)

add_compile_definitions(TESTING)

add_executable(chunker_test chunker_test.c xorshift32.c ../chunker.c ../chunk.c ../sha.c ../log.c ../utils.c)
target_include_directories(chunker_test PRIVATE ${PROJECT_SOURCE_DIR} ${CURRENT_SOURCE_DIR} ${CMOCKA_INCLUDES})
target_link_libraries(chunker_test PRIVATE ${CMOCKA_LIBRARIES} ${CRYPTO_LIBRARIES})
add_test(chunker_test chunker_test)

add_executable(sha_test sha_test.c xorshift32.c ../sha.c ../log.c ../utils.c)
target_include_directories(sha_test PRIVATE ${PROJECT_SOURCE_DIR} ${CURRENT_SOURCE_DIR} ${CMOCKA_INCLUDES})
target_link_libraries(sha_test PRIVATE ${CMOCKA_LIBRARIES} ${CRYPTO_LIBRARIES})
add_test(sha_test sha_test)
