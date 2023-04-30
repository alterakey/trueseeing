from python:3.9-alpine as builder
run apk add openjdk17-jdk

from python:3.9-alpine
run apk add --no-cache openjdk17-jre-headless zip
copy --from=0 /usr/lib/jvm/java-17-openjdk/bin/jarsigner /usr/lib/jvm/java-17-openjdk/bin/
# https://github.com/iBotPeaches/Apktool
copy apktool.jar /app/apktool.jar
# https://github.com/Iyxan23/zipalign-java
copy zipalign.jar /app/zipalign.jar
copy disasm.py /app/disasm.py
copy genkey.py /app/genkey.py
copy unsign.py /app/unsign.py
copy resign.py /app/resign.py
copy asm.py /app/asm.py
copy sign.py /app/sign.py
copy zipalign.py /app/zipalign.py
run chmod 755 /app/*.py && mkdir /out
env PATH=/app:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
workdir /out