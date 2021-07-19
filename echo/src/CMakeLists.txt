# Note that headers are optional, and do not affect add_library, but they will not
# show up in IDEs unless they are listed in add_library.

set(HEADER_LIST
        "${dc_echo_SOURCE_DIR}/include/echo.h"
        )

set(SERVER_SOURCE_LIST
        "server.c"
        )

set(CLIENT_SOURCE_LIST
        "client.c")

add_definitions( -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 )

if(APPLE)
    add_definitions( -D_DARWIN_C_SOURCE )
endif()

set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*,-llvmlibc-restrict-system-libc-headers,-cppcoreguidelines-init-variables,-clang-analyzer-security.insecureAPI.strcpy,-concurrency-mt-unsafe,-android-cloexec-accept,-android-cloexec-dup,-google-readability-todo,-cppcoreguidelines-avoid-magic-numbers,-readability-magic-numbers;--quiet")

# Make a executables
add_executable(dc_echo_server ${SERVER_SOURCE_LIST} ${HEADER_LIST})
add_executable(dc_echo_client ${CLIENT_SOURCE_LIST} ${HEADER_LIST})

# We need this directory, and users of our library will need it too
target_include_directories(dc_echo_server PRIVATE ../include)
target_include_directories(dc_echo_server PRIVATE /usr/include)
target_include_directories(dc_echo_server PRIVATE /usr/local/include)
target_link_directories(dc_echo_server PRIVATE /usr/lib)
target_link_directories(dc_echo_server PRIVATE /usr/local/lib)

target_include_directories(dc_echo_client PRIVATE ../include)
target_include_directories(dc_echo_client PRIVATE /usr/include)
target_include_directories(dc_echo_client PRIVATE /usr/local/include)
target_link_directories(dc_echo_client PRIVATE /usr/lib)
target_link_directories(dc_echo_client PRIVATE /usr/local/lib)

# All users of this library will need at least C11
target_compile_features(dc_echo_server PUBLIC c_std_11)
target_compile_options(dc_echo_server PRIVATE -g)
target_compile_options(dc_echo_server PRIVATE -fstack-protector-all -ftrapv)
target_compile_options(dc_echo_server PRIVATE -Wpedantic -Wall -Wextra)
target_compile_options(dc_echo_server PRIVATE -Wdouble-promotion -Wformat-nonliteral -Wformat-security -Wformat-y2k -Wnull-dereference -Winit-self -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wunused-local-typedefs -Wstrict-overflow=5 -Wmissing-noreturn -Walloca -Wfloat-equal -Wdeclaration-after-statement -Wshadow -Wpointer-arith -Wabsolute-value -Wundef -Wexpansion-to-defined -Wunused-macros -Wno-endif-labels -Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings -Wconversion -Wdangling-else -Wdate-time -Wempty-body -Wsign-conversion -Wfloat-conversion -Waggregate-return -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wpacked -Wpadded -Wredundant-decls -Wnested-externs -Winline -Winvalid-pch -Wlong-long -Wvariadic-macros -Wdisabled-optimization -Wstack-protector -Woverlength-strings )

target_compile_features(dc_echo_client PUBLIC c_std_11)
target_compile_options(dc_echo_client PRIVATE -g)
target_compile_options(dc_echo_client PRIVATE -fstack-protector-all -ftrapv)
target_compile_options(dc_echo_client PRIVATE -Wpedantic -Wall -Wextra)
target_compile_options(dc_echo_client PRIVATE -Wdouble-promotion -Wformat-nonliteral -Wformat-security -Wformat-y2k -Wnull-dereference -Winit-self -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wunused-local-typedefs -Wstrict-overflow=5 -Wmissing-noreturn -Walloca -Wfloat-equal -Wdeclaration-after-statement -Wshadow -Wpointer-arith -Wabsolute-value -Wundef -Wexpansion-to-defined -Wunused-macros -Wno-endif-labels -Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings -Wconversion -Wdangling-else -Wdate-time -Wempty-body -Wsign-conversion -Wfloat-conversion -Waggregate-return -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wpacked -Wpadded -Wredundant-decls -Wnested-externs -Winline -Winvalid-pch -Wlong-long -Wvariadic-macros -Wdisabled-optimization -Wstack-protector -Woverlength-strings )

find_library(LIBM m REQUIRED)
if(LIBM)
    target_link_libraries(dc_echo_server ${LIBM})
    target_link_libraries(dc_echo_client ${LIBM})
endif()

find_library(LIBDC_POSIX dc_posix REQUIRED)
if(LIBDC_POSIX)
    target_link_libraries(dc_echo_server ${LIBDC_POSIX})
    target_link_libraries(dc_echo_client ${LIBDC_POSIX})
endif()

find_library(LIBDC_UTIL dc_util REQUIRED)
if(LIBDC_UTIL)
    target_link_libraries(dc_echo_server ${LIBDC_UTIL})
    target_link_libraries(dc_echo_client ${LIBDC_UTIL})
endif()

find_library(LIBDC_FSM dc_fsm REQUIRED)
if(LIBDC_FSM)
    target_link_libraries(dc_echo_server ${LIBDC_FSM})
    target_link_libraries(dc_echo_client ${LIBDC_FSM})
endif()

find_library(LIBDC_NETWORK dc_network REQUIRED)
if(LIBDC_NETWORK)
    target_link_libraries(dc_echo_server ${LIBDC_NETWORK})
    target_link_libraries(dc_echo_client ${LIBDC_NETWORK})
endif()

find_library(LIBDC_APPLICATION dc_application REQUIRED)
if(LIBDC_UTIL)
    target_link_libraries(dc_echo_server ${LIBDC_APPLICATION})
    target_link_libraries(dc_echo_client ${LIBDC_APPLICATION})
endif()

find_library(LIBCONFIG config REQUIRED)
if(LIBCONFIG)
    target_link_libraries(dc_echo_server ${LIBCONFIG})
    target_link_libraries(dc_echo_client ${LIBCONFIG})
endif()

# set_target_properties(dc_echo_server PROPERTIES OUTPUT_NAME "dcecho")
# install(TARGETS dc_echo DESTINATION bin)

# IDEs should put the headers in a nice place
source_group(
        TREE "${PROJECT_SOURCE_DIR}/include"
        PREFIX "Header Files"
        FILES ${HEADER_LIST}
)
