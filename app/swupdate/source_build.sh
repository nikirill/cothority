#!/usr/bin/env bash

cd ReleaseSource
git checkout $1
bash ../building.sh
cd ..
