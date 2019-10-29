cmake_minimum_required(VERSION 2.8)

# Function for building single algorithm
function(buildAlgorithm ALGO_NAME)
	SET(ALGO_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/${ALGO_NAME})
	message(STATUS "Generating project file for algo in ${ALGO_FOLDER}")
    
    file(GLOB_RECURSE HEADERS ${ALGO_FOLDER}/*.hpp ${ALGO_FOLDER}/*.h)
	file(GLOB SOURCE *.cpp ${HEADERS} ${ALGO_FOLDER}/*.cpp)
    
    if(${ALGO_NAME} STREQUAL digital_signature)
		file(GLOB ADD_SOURCE "../external/bigint/*.cc")
		SET(SOURCE ${SOURCE} ${ADD_SOURCE})
	endif()
    
    add_executable(${ALGO_NAME} ${SOURCE})
    
    if(NOT ${ALGO_NAME} STREQUAL ${WALL_IGNORE})
        if(MSVC)
            target_compile_options(${ALGO_NAME} PRIVATE /W4 /WX)
        else()
            target_compile_options(${ALGO_NAME} PRIVATE -Wall -Wextra -pedantic -Werror)
        endif()
	endif()
    
    target_link_libraries(${ALGO_NAME} common)
endfunction(buildAlgorithm)

set(ALGORITHMS
    des
    rsa
    feistel_gost
    hash_gost
    digital_signature
)

set(WALL_IGNORE
    digital_signature
)

# Build all algorithms
function(buildAlgorithms)
	foreach(ALGO ${ALGORITHMS})
		buildAlgorithm(${ALGO})
	endforeach(ALGO)
endfunction(buildAlgorithms)

buildAlgorithms()
