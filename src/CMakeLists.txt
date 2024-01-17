project(${ROOT_PROJECT_NAME})

file(GLOB SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
                 ${CMAKE_CURRENT_SOURCE_DIR}/*.cc
                 ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

file(GLOB HEADER ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp
                 ${CMAKE_CURRENT_SOURCE_DIR}/*.h)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_library(${PROJECT_NAME} SHARED ${SOURCE} ${HEADER})
#target_link_libraries(${PROJECT_NAME} ...)

set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE CXX)

install(TARGETS ${PROJECT_NAME} 
        RUNTIME DESTINATION ${BIN_DIR}
        LIBRARY DESTINATION ${BIN_DIR}
        ARCHIVE DESTINATION ${BIN_DIR})