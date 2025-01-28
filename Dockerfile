from python:3.13-slim
run pip install flit
copy . /tmp/build/
run (cd /tmp/build && flit build)

from python:3.13-slim
run apt-get update -y && apt-get install -y openjdk-17-jre-headless zip adb
run install -d -m 777 /data /ext /cache /out && ln -sfn /cache /root/.local
copy --from=0 /tmp/build/dist/*.whl /tmp/dist/
run pip install /tmp/dist/*.whl && rm -rf /tmp/dist /tmp/ext
env PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
env TS2_IN_DOCKER=1
env TS2_CACHEDIR=/cache
env TS2_HOME=/data
env TS2_EXTDIR=/ext
env TS2_SWIFT_DEMANGLER_URL=http://ts2-swift-demangle
workdir /out
entrypoint ["trueseeing"]
