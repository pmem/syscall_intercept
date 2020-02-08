mkdir build && \
cd build && \
cmake .. -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE && \
make VERBOSE=1 && \
ctest -V
