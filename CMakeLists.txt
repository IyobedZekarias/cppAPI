cmake_minimum_required(VERSION 3.2.0)
project(cppAPI VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

include_directories(/usr/local/include)
include_directories(CMAKE_CURRENT_SOURCE_DIR)
find_library(PTHREAD_LIBRARY pthread HINTS /usr/lib/x86_64-linux-gnu)

find_library(GMPWOOP_LIBRARY gmp HINTS /usr/local/lib)

find_library(CRYPTOIZ_LIBRARY crypto_iz HINTS usr/local/lib)

# add_definitions(-DCROW_ENABLE_SSL)

# add_executable(cppAPI main.cpp base64.cpp)
add_executable(cppAPI tester.cpp)

# target_link_libraries(cppAPI ${CRYPTO_LIBRARY} ${SSL_LIBRARY} ${PTHREAD_LIBRARY})
target_link_libraries(cppAPI ${GMPWOOP_LIBRARY} ${PTHREAD_LIBRARY} ${CRYPTOIZ_LIBRARY})

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})