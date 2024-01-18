project(${ROOT_PROJECT_NAME})

#embed private key
set(gen_filename private_key)
set(output_c "#include \"private_key.h\"")
set(output_h "#ifndef ${gen_filename}_H\n#define ${gen_filename}_H\n#include <stdint.h>\n")

function(EMBED_RESOURCE read_file var_name)
        message("${read_file}, ${var_name}")
        file(READ ${read_file} content HEX)
        set(counter 0)
        set(content_c "")
        string(REGEX MATCHALL "([A-Fa-f0-9][A-Fa-f0-9])" separated_hex "${content}")
        foreach(hex IN LISTS separated_hex)
                string(APPEND content_c "0x${hex}, ")
                math(EXPR counter "${counter} + 1")
                if(${counter} GREATER 16)
                        string(APPEND content_c "\n")
                        set(counter 0)
                endif()
        endforeach()

        set(output_c "${output_c}\nconst uint8_t ${var_name}[] = {${content_c}};\nconst uint32_t ${var_name}_len = sizeof(${var_name});\n" PARENT_SCOPE)
        set(output_h "${output_h}\nextern const uint8_t ${var_name}[];\nextern const uint32_t ${var_name}_len;\n" PARENT_SCOPE)
endfunction()

EMBED_RESOURCE(${CMAKE_SOURCE_DIR}/key/private-key.pem RESOURCE_PRIVATE_KEY)
set(output_h "${output_h}\n#endif\n")
file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/${gen_filename}.h "${output_h}")
file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/${gen_filename}.c "${output_c}")

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

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E remove
                   ${CMAKE_CURRENT_SOURCE_DIR}/${gen_filename}.h 
                   ${CMAKE_CURRENT_SOURCE_DIR}/${gen_filename}.c)