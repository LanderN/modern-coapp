cmake_minimum_required(VERSION 3.16.3)
set (CMAKE_CXX_STANDARD 17)

project(modern-coapp LANGUAGES CXX VERSION 0.0.1)

# Includes
Include(FetchContent)

# Test framework
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v2.13.6)
FetchContent_MakeAvailable(Catch2)

add_executable(tests test.cpp)
target_link_libraries(tests PRIVATE Catch2::Catch2)

# Enable warnings
target_compile_options(tests PRIVATE
  $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
  $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -pedantic -Werror>
)