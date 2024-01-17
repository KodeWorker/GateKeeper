project(GateKeeper)
set(ROOT_PROJECT_NAME ${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(BIN_DIR ${PROJECT_SOURCE_DIR}/bin)
set(KEY_DIR ${PROJECT_SOURCE_DIR}/key)

set(${CMAKE_MODULE_PATH} ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

add_subdirectory(src)
add_subdirectory(test)
add_subdirectory(app)
