cmake_minimum_required(VERSION 3.15)
project(${PROJECT_NAME}_test)

set(GTEST_REPOSITORY https://github.com/google/googletest.git)
set(GTEST_TAG v1.14.0)

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY ${GTEST_REPOSITORY}
    GIT_TAG ${GTEST_TAG}
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF)
FetchContent_MakeAvailable(googletest)

enable_testing()

file(GLOB SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
                 ${CMAKE_CURRENT_SOURCE_DIR}/*.cc
                 ${CMAKE_CURRENT_SOURCE_DIR}/*.c
                 ${CMAKE_SOURCE_DIR}/src/*.cpp
                 ${CMAKE_SOURCE_DIR}/src/*.cc
                 ${CMAKE_SOURCE_DIR}/src/*.c)

file(GLOB HEADER ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp
                 ${CMAKE_CURRENT_SOURCE_DIR}/*.h
                 ${CMAKE_SOURCE_DIR}/src/*.hpp
                 ${CMAKE_SOURCE_DIR}/src/*.h)

include_directories(${CMAKE_SOURCE_DIR}/include)
add_executable(${PROJECT_NAME} ${SOURCE} ${HEADER})

target_link_libraries(${PROJECT_NAME} 
                      debug ${ROOT_PROJECT_NAME}
                      optimized ${ROOT_PROJECT_NAME}
                      GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME})

install(TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION ${BIN_DIR})