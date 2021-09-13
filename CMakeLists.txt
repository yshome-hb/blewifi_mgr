cmake_minimum_required(VERSION 3.0)

project(blewifi_mgr)

include_directories(includes)
include_directories(includes/src/shared)
include_directories(includes/lib)
include_directories(includes)

add_subdirectory(libbluetooth)
add_subdirectory(libshared)

# blewifi_mgr
add_executable(blewifi_mgr
    src/blewifi_manager.c
    src/ble_advertise.c
    src/gatt_server.c
    src/network_util.c)

target_link_libraries(blewifi_mgr bluetooth shared pthread cjson)

