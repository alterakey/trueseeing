from python:3.9-alpine
run apk add openjdk17-jre-headless
copy disasm.py /app/disasm.py
copy apktool.jar /app/apktool.jar
run chmod 755 /app/*.py && mkdir /out
env PATH=/app:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
workdir /out