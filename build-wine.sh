#!/bin/bash



pushd wine-build

if [[ -e "./out" ]]; then
	echo "the temporary output dir: 'out' exists, please delete!"
	exit 1
fi


docker build -t nk/wine-build .


mkdir -p out 
git clone .. out/pynitrokey


docker run "$@" --mount type=bind,source="$(pwd)"/out,target=/build/wine_base/drive_c/build nk/wine-build



popd
