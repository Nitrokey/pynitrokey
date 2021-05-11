#!/bin/bash
set -euxo pipefail
# defeine masked variable $GITHUB_TOKEN in gitlab webinterface: Reposetorry -> Settings -> CI/CD ->Variables
# GITHUB_TOKEN can be crataed at https://github.com/settings/tokens (from machine user account)
# set privileges to full repo
# USAGE create annotated tag e.g.: v0.4.2.nitrokey (changing the name format will break things)
# run ./releas.sh

repo=Nitrokey/pynitrokey

release_name=$(git describe)

file_version=${release_name%.*}
file_version=${file_version#v}


#$(cat pynitrokey/VERSION)
#a="${version%.*.*}"
#b="${version#*.*.}"
#a=$(echo $a | awk -F. -v OFS=. 'NF==1{print ++$NF}; NF>1{$NF=sprintf("%0*d", length($NF), ($NF+1)); print}')
#version=$a.$b

upload_url=$(curl -s -H "Authorization: token $GITHUB_TOKEN" -d '{"tag_name": "'"$release_name"'", "name":"'"$release_name"'","body":""}' "https://api.github.com/repos/$repo/releases" | jq -r '.upload_url')
echo release_name:
echo $release_name
echo file_version:
echo $file_version
upload_url="${upload_url%\{*}"


echo "uploading asset to release to url : $upload_url"

curl -s -H "Authorization: token $GITHUB_TOKEN"  \
        -H "Content-Type: application/vnd.microsoft.portable-executable" \
        --data-binary @wine-build/nitropy-$file_version.exe  \
        "$upload_url?name=nitropy-$file_version.exe"

curl -s -H "Authorization: token $GITHUB_TOKEN"  \
        -H "Content-Type: application/octet-stream" \
        --data-binary @wine-build/pynitrokey-$file_version-win32.msi  \
        "$upload_url?name=pynitrokey-$file_version-win32.msi"