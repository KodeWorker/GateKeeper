project(${ROOT_PROJECT_NAME}_app)

file(GLOB SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
                 ${CMAKE_CURRENT_SOURCE_DIR}/*.cc
                 ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

file(GLOB HEADER ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp
                 ${CMAKE_CURRENT_SOURCE_DIR}/*.h)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(${PROJECT_NAME} ${SOURCE} ${HEADER})

target_link_libraries(${PROJECT_NAME} 
                      debug ${ROOT_PROJECT_NAME}
                      optimized ${ROOT_PROJECT_NAME})

install(TARGETS ${PROJECT_NAME} DESTINATION ${BIN_DIR})