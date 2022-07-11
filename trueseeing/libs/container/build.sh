#!/bin/sh
here=$(dirname $0)
version="$1"
cd $here
docker buildx build --platform linux/arm64,linux/amd64 -f Dockerfile -t alterakey/trueseeing-apk:$version --push .
docker buildx build --platform linux/amd64 -f Dockerfile-zipalign -t alterakey/trueseeing-apk-zipalign:$version --push .
