from python:3.9-alpine
run pip install flit
copy . /tmp/build/
run (cd /tmp/build && flit build)

from python:3.9-alpine
run mkdir /tmp/dist
# Building LIEF takes a long time so fetch from our wheel cache
add https://github.com/alterakey/trueseeing-lief/raw/main/dist/lief-0.14.1-cp39-cp39-musllinux_1_2_aarch64.whl /tmp/dist
add https://github.com/alterakey/trueseeing-lief/raw/main/dist/lief-0.14.1-cp39-cp39-musllinux_1_2_x86_64.whl /tmp/dist
# .. if you really prefer building it, comment above and uncomment below
#run (cd /tmp/dist && pip download 'lief~=0.14') || (apk add --no-cache build-base ninja cmake git ccache && git clone -b 0.14.1 https://github.com/lief-project/LIEF.git /tmp/build && (cd /tmp/build/api/python && pip install -r build-requirements.txt && pyproject-build -w && cp -a dist/*.whl /tmp/dist/))

from python:3.9-alpine
run apk add --no-cache openjdk17-jre-headless zip android-tools
run mkdir /data /ext /cache /out && ln -sfn /cache /root/.local
copy --from=0 /tmp/build/dist/*.whl /tmp/dist/
copy --from=1 /tmp/dist/*.whl /tmp/ext/
run pip install -f /tmp/ext/ /tmp/dist/*.whl && rm -rf /tmp/dist /tmp/ext
env PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
env TS2_IN_DOCKER=1
env TS2_CACHEDIR=/cache
env TS2_HOME=/data
env TS2_EXTDIR=/ext
env TS2_SWIFT_DEMANGLER_URL=http://ts2-swift-demangle
workdir /out
entrypoint ["trueseeing"]
