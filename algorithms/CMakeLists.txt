# Function for building single example
function(buildAlgorithm ALGO_NAME)
	SET(ALGO_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/${EXAMPLE_NAME})
	message(STATUS "Generating project file for example in ${ALGO_FOLDER}")
	# Main
	file(GLOB SOURCE *.cpp ${BASE_HEADERS} ${ALGO_FOLDER}/*.cpp)
	SET(MAIN_CPP ${ALGO_FOLDER}/main.cpp)
    
	set_target_properties(${ALGO_NAME} PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
endfunction(buildExample)

# Build all algorithms
function(buildAlgorithms)
	foreach(algo ${ALGORITHMS})
		buildAlgorithm(${ALGORITHMS})
	endforeach(algo)
endfunction(buildAlgorithms)

set(ALGORITHMS
	des
)

buildAlgorithms()
