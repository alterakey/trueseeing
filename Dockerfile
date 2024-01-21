from python:3.9-alpine
run pip install flit
copy . /tmp/build/
run (cd /tmp/build && flit build)

from python:3.9-alpine
run apk add --no-cache openjdk17-jre-headless zip android-tools
run mkdir /data /ext /cache /out && ln -sfn /cache /root/.local
copy --from=0 /tmp/build/dist/*.whl /tmp/dist/
run pip install /tmp/dist/*.whl && rm -rf /tmp/dist
env PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
env TS2_IN_DOCKER=1
env TS2_CACHEDIR=/cache
env TS2_HOME=/data
env TS2_EXTDIR=/ext
workdir /out
entrypoint ["trueseeing"]
