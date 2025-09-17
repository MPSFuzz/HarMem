cmake_minimum_required(VERSION 3.16)
project(aflgo_npm_pass LANGUAGES CXX)

set(LLVM_DIR "/opt/llvm21/lib/cmake/llvm")
find_package(LLVM REQUIRED CONFIG)
if (LLVM_PACKAGE_VERSION VERSION_LESS "21.0.0")
  message(FATAL_ERROR "Require LLVM >= 21, found ${LLVM_PACKAGE_VERSION}")
endif()
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(AddLLVM OPTIONAL)

if (COMMAND add_llvm_pass_plugin)
  add_llvm_pass_plugin(aflgo-npm-pass
    aflgo-npm-pass.so.cc
  )
  target_include_directories(aflgo-npm-pass PRIVATE ${LLVM_INCLUDE_DIRS})
  target_compile_definitions(aflgo-npm-pass PRIVATE ${LLVM_DEFINITIONS})
  set_target_properties(aflgo-npm-pass PROPERTIES POSITION_INDEPENDENT_CODE ON)
else()
  add_library(aflgo-npm-pass MODULE aflgo-npm-pass.so.cc)
  set_target_properties(aflgo-npm-pass PROPERTIES
    PREFIX ""  # 输出名就是 aflgo-npm-pass.so
    POSITION_INDEPENDENT_CODE ON
  )
  target_include_directories(aflgo-npm-pass PRIVATE ${LLVM_INCLUDE_DIRS})
  target_compile_definitions(aflgo-npm-pass PRIVATE ${LLVM_DEFINITIONS})
  # ⚠️ 这里故意不写任何 LLVM 链接库
endif()
