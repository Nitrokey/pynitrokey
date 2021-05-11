#!/bin/bash
set -euo pipefail
# nightly_upload: checks remote file for changes and uploads new version if necessary
# Usage:
# set scp(ssh) server with user and path
# create env-variable with private key:
# $ssh_server_key(delete first and last line)
# $ssh_port Port in hex has to be 8digits e.g:000008BF
# $ssh_address e.g.: user@www.internet.com:/root/ci/
# call script: ./nightly_upload.sh -filename

repo_name=$(basename `git rev-parse --show-toplevel`)
echo repo_name
ssh=$ssh_address$repo_name'/'
port=$(echo $(( 16#$ssh_port )))
build_file="$1"
new_sha=$build_file"-sha256sum.txt"

old_sha="old"-$new_sha
date_now=$(date "+%F-%H-%M-%S")

# create ssh-key file
echo "-----BEGIN OPENSSH PRIVATE KEY-----" > ~/server_key
echo "$ssh_server_key" >> ~/server_key
echo "-----END OPENSSH PRIVATE KEY-----" >> ~/server_key

chmod 600 ~/server_key
cat ~/server_key

sha256sum $build_file > $new_sha
if ! rsync -e "ssh -p $port -i ~/server_key" $ssh$new_sha $old_sha; then
  echo No old sha file on server
fi

if cmp -s $new_sha $old_sha; then
    echo Build is unchanged
else
    rsync -e "ssh -p $port -i ~/server_key" $new_sha $ssh$new_sha
    rsync -e "ssh -p $port -i ~/server_key" $build_file $ssh"nightly_build-"$date_now$build_file
    echo Build was uploaded
fi