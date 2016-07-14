#!/usr/bin/env bash

# Take the arguments
path=$1
commitid=$2

# Clone repo and pull signatures
#git clone $path ./ReleaseSource
cd ./ReleaseSource/
git fetch origin refs/notes/signatures:refs/notes/signatures
echo "$(git notes --ref=signatures show $commitid)"
cp policy.toml ../
cp building.sh ../
cd ..