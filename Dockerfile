from python:3.13-slim-bookworm
run apt-get update -y
run apt-get install -y --no-install-recommends git
run pip install --no-cache-dir uv
copy . /usr/lib/ts2
run bash -c "cd /usr/lib/ts2 && uv sync --active --locked --no-dev"
run (cd /usr/lib && git clone https://github.com/alterakey/ts2-frida-ios-dump.git frida-ios-dump && cd frida-ios-dump && uv venv && uv pip install -r ./requirements.txt)

from python:3.13-slim-bookworm
run apt-get update -y
run apt-get install -y --no-install-recommends openjdk-17-jre-headless zip adb && rm -rf /var/lib/apt/lists/*
run install -d -m 777 /data /ext /cache /out && ln -sfn /cache /root/.local
copy --from=0 /usr/lib/frida-ios-dump /usr/lib/frida-ios-dump
copy --from=0 /usr/lib/ts2 /usr/lib/ts2
env PATH=/usr/lib/ts2/.venv/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin
env TS2_IN_DOCKER=1
env TS2_CACHEDIR=/cache
env TS2_HOME=/data
env TS2_EXTDIR=/ext
env TS2_FRIDA_IOS_DUMP_PATH=/usr/lib/frida-ios-dump/dump.py
env TS2_FRIDA_IOS_DUMP_INTERP=/usr/lib/frida-ios-dump/.venv/bin/python3
env TS2_SWIFT_DEMANGLER_URL=http://ts2-swift-demangle
workdir /out
entrypoint ["trueseeing"]
