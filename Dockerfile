from python:3.13-slim-bookworm
run pip install flit
copy . /tmp/build/
run (cd /tmp/build && flit build)

from python:3.13-slim-bookworm
run apt-get update -y && apt-get install -y git
run (cd /opt && git clone https://github.com/alterakey/ts2-frida-ios-dump.git frida-ios-dump && cd frida-ios-dump && python3 -m venv .venv && .venv/bin/pip install -r ./requirements.txt)

from python:3.13-slim-bookworm
run apt-get update -y && apt-get install -y openjdk-17-jre-headless zip adb
run install -d -m 777 /data /ext /cache /out && ln -sfn /cache /root/.local
copy --from=1 /opt/frida-ios-dump /opt/frida-ios-dump
copy --from=0 /tmp/build/dist/*.whl /tmp/dist/
run pip install /tmp/dist/*.whl && rm -rf /tmp/dist /tmp/ext
env PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
env TS2_IN_DOCKER=1
env TS2_CACHEDIR=/cache
env TS2_HOME=/data
env TS2_EXTDIR=/ext
env TS2_FRIDA_IOS_DUMP_PATH=/opt/frida-ios-dump/dump.py
env TS2_FRIDA_IOS_DUMP_INTERP=/opt/frida-ios-dump/.venv/bin/python3
env TS2_SWIFT_DEMANGLER_URL=http://ts2-swift-demangle
workdir /out
entrypoint ["trueseeing"]
