Title: dhcpv4 APIs

Description:

This test verifies the dhcpv4 subsystem

--------------------------------------------------------------------------------

Fuzzing:

This project can be fuzzed with AFL:

# Open a file descriptor to send fuzz target output to (optional)
exec 3<>/dev/udp/127.0.0.1/7777
export AFL_TARGET_FD=3

# Increase the memory limit
export LIMIT_MB=500
ulimit -Sv $[LIMIT_MB << 10]

# 
export FUZZING_MODE=offer

# Build the project
mkdir build/
cd build
cmake -GNinja -DBOARD=native_posix -DCONFIG_ASAN=n -DCONFIG_NO_OPTIMIZATIONS=y ..
ninja

# Check that everything is working
./zephyr/zephyr.elf < ../testcase_dir/$FUZZING_MODE/packet_$FUZZING_MODE

# Fuzz with AFL
cd ..
AFL_NO_FORKSRV=1 afl-fuzz -m $LIMIT_MB \
  -i testcase_dir/$FUZZING_MODE \
  -o findings_dir/$FUZZING_MODE -- ./build/zephyr/zephyr.elf
