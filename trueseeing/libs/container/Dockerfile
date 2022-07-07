from python:3.9-alpine
run apk add openjdk17-jdk zip
copy apktool.jar /app/apktool.jar
copy disasm.py /app/disasm.py
copy genkey.py /app/genkey.py
copy unsign.py /app/unsign.py
copy resign.py /app/resign.py
copy asm.py /app/asm.py
copy sign.py /app/sign.py
run chmod 755 /app/*.py && mkdir /out
env PATH=/app:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
workdir /out