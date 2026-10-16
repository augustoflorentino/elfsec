cmake_minimum_required(VERSION 3.16)
project(elfsec VERSION 0.5.0 DESCRIPTION "ELF hardening profile: protections, imports and dependencies read from memory" LANGUAGES C)

option(ELFSEC_BUILD_TESTS "Build tests" OFF)
option(ELFSEC_BUILD_EXAMPLES "Build examples" OFF)
option(ELFSEC_BUILD_FUZZ "Build libFuzzer targets" OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

add_library(elfsec src/elfsec.c src/elfs_read.c src/elfs_dyn.c src/elfs_profile.c src/elfs_prop.c)
add_library(elfsec::elfsec ALIAS elfsec)
target_include_directories(elfsec PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
set_target_properties(elfsec PROPERTIES
    C_STANDARD 99
    C_VISIBILITY_PRESET hidden
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

set(PC_CFLAGS "")
if(BUILD_SHARED_LIBS)
    target_compile_definitions(elfsec PRIVATE ELFS_BUILD_SHARED INTERFACE ELFS_SHARED)
    set(PC_CFLAGS "-DELFS_SHARED")
endif()

install(TARGETS elfsec EXPORT elfsecTargets)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT elfsecTargets
    NAMESPACE elfsec::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/elfsec)

configure_package_config_file(cmake/elfsecConfig.cmake.in
    ${PROJECT_BINARY_DIR}/elfsecConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/elfsec)
write_basic_package_version_file(${PROJECT_BINARY_DIR}/elfsecConfigVersion.cmake
    COMPATIBILITY SameMajorVersion)
install(FILES
    ${PROJECT_BINARY_DIR}/elfsecConfig.cmake
    ${PROJECT_BINARY_DIR}/elfsecConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/elfsec)

configure_file(elfsec.pc.in ${PROJECT_BINARY_DIR}/elfsec.pc @ONLY)
install(FILES ${PROJECT_BINARY_DIR}/elfsec.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if(ELFSEC_BUILD_TESTS)
    enable_testing()
    add_executable(test_elfsec tests/test_elfsec.c)
    target_link_libraries(test_elfsec PRIVATE elfsec)
    target_compile_definitions(test_elfsec PRIVATE ELFS_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors")
    add_test(NAME elfsec COMMAND test_elfsec)
    add_executable(elfs_dump tests/elfs_dump.c)
    target_link_libraries(elfs_dump PRIVATE elfsec)
    add_library(elfsec_header_check OBJECT tests/header_check.c)
    target_include_directories(elfsec_header_check PRIVATE include)
    set_target_properties(test_elfsec elfs_dump elfsec_header_check PROPERTIES C_STANDARD 99)
endif()

if(ELFSEC_BUILD_EXAMPLES)
    add_executable(elfsec_example examples/elfsec.c)
    target_link_libraries(elfsec_example PRIVATE elfsec)
    set_target_properties(elfsec_example PROPERTIES C_STANDARD 99)
endif()

if(ELFSEC_BUILD_FUZZ)
    add_executable(fuzz_elfsec fuzz/fuzz_elfsec.c)
    target_link_libraries(fuzz_elfsec PRIVATE elfsec)
    target_link_options(fuzz_elfsec PRIVATE -fsanitize=fuzzer)
endif()
