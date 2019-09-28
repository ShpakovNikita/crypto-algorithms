# Function for building single algorithm
function(buildAlgorithm ALGO_NAME)
	SET(ALGO_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/${ALGO_NAME})
	message(STATUS "Generating project file for algo in ${ALGO_FOLDER}")
    
    file(GLOB_RECURSE HEADERS ${ALGO_FOLDER}/*.hpp ${ALGO_FOLDER}/*.h)
	file(GLOB SOURCE *.cpp ${HEADERS} ${ALGO_FOLDER}/*.cpp)
    
    add_executable(${ALGO_NAME} ${SOURCE})
    
    target_link_libraries(${ALGO_NAME})
endfunction(buildAlgorithm)

set(ALGORITHMS
    des
    rsa
)

# Build all algorithms
function(buildAlgorithms)
	foreach(ALGO ${ALGORITHMS})
		buildAlgorithm(${ALGO})
	endforeach(ALGO)
endfunction(buildAlgorithms)

buildAlgorithms()
