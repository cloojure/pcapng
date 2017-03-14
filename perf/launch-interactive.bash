#!/bin/bash -v
# docker run --privileged --cap-add ALL       -it --name=perf-interactive --net bridge --pid=host \
# docker run --privileged --cap-add NET_ADMIN -it --name=perf-interactive --net host   --pid=host \
  docker run              --cap-add ALL       -it --name=perf-interactive --net host   --pid=host \
  -v /usr/src:/usr/src \
  -v /lib/modules:/lib/modules \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /home/alan/brcd/pcapng/perf:/x/perf \
  perf-1 \
  /bin/bash

#   sudo tcpreplay --intf1=wlp4s0  --verbose --pps=10 /x/perf/ISIS_level2_adjacency.cap  

#   sudo tcpreplay --intf1=eth0    --verbose --pps=10 /x/perf/ISIS_level2_adjacency.cap  

#   sudo tcpreplay --intf1=enp0s3  --verbose --pps=10 ISIS_level2_adjacency.cap  

