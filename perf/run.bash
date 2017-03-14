#!/bin/bash -v
docker run --privileged -it --name=perf-cont --net host --pid=host \
  -v /usr/src:/usr/src \
  -v /lib/modules:/lib/modules \
  -v /sys/kernel/debug:/sys/kernel/debug \
  perf-1 \
  /bcc/examples/hello_world.py
