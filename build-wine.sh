#!/bin/bash

pushd wine-build

if [[ -e "./out" ]]; then
	echo "the temporary output dir: 'wine-build/out' exists, please delete!"
	exit 1
fi
docker build -t nk/wine-build .

mkdir -p out 
git clone .. out/pynitrokey

docker run "$@" --mount type=bind,source="$(pwd)"/out,target=/build/wine_base/drive_c/build nk/wine-build

popd


echo "######################"
echo "to debug (enter the docker after building) just pass '-it' to this script!"
echo "additionally inside do: $ export WINEPREFIX=/build/wine_base "
echo "... this will allow direct usage of 'wine' with the correct wine-base-dir"
echo "######################"




