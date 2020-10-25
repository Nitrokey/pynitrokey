#!/bin/bash



pushd wine-build

rm -rf out

docker build -t nk/wine-build .


mkdir -p out 

docker run "$@" --mount type=bind,source="$(pwd)"/out,target=/build/wine_base/drive_c/build nk/wine-build



popd
