from python:3.11-alpine
run apk add --no-cache openjdk17-jre-headless zip
run mkdir /data /cache /out && ln -sfn /cache /root/.local
arg dist
copy $dist /tmp/dist/
run pip install /tmp/dist/*.whl && rm -rf /tmp/dist
env PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
env TS2_IN_DOCKER=1
env TS2_CACHEDIR=/cache
env TS2_HOME=/data
workdir /out
entrypoint ["trueseeing"]
