FROM docker.io/library/alpine@sha256:1829893486be257df5049ab3b7fc95afbd0fc09d89803cbc580bda1ba5386b29
ARG SOURCE_DATE_EPOCH=1795046400
COPY libcrypto3.apk libssl3.apk /verified/
RUN apk add --no-network /verified/libcrypto3.apk /verified/libssl3.apk && rm -rf /verified && rm -f /var/log/apk.log
