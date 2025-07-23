# Install script for directory: /workspaces/longfellow-zk/lib

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/workspaces/longfellow-zk/install")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/workspaces/longfellow-zk/clang-build-release/testing/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/util/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/algebra/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/arrays/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/merkle/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/proto/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/random/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/sumcheck/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/gf2k/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/cbor/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/ec/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/zk/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/circuits/anoncred/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/circuits/base64/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/circuits/cbor_parser/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/circuits/compiler/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/circuits/ecdsa/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/circuits/jwt/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/circuits/logic/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/circuits/mac/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/circuits/mdoc/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/circuits/sha/cmake_install.cmake")
  include("/workspaces/longfellow-zk/clang-build-release/circuits/sha3/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/workspaces/longfellow-zk/clang-build-release/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
