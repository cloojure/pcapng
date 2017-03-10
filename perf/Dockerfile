FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    apt-transport-https \
    git \
    lsb-release \
    net-tools \
    python \
    python-pip \
    sudo \
    tcpreplay \
    vim \
    linux-generic netperfmeter iperf arping 

RUN echo "deb [trusted=yes] https://repo.iovisor.org/apt/xenial xenial-nightly main" | \
      tee /etc/apt/sources.list.d/iovisor.list
RUN apt-get update && apt-get install -y bcc-tools 
# libelf1 libbcc-examples linux-libc-dev

RUN pip install --upgrade pip 
RUN pip install bcc

# RUN apt-get install -y bison build-essential cmake flex git libedit-dev \
#            libllvm3.7 llvm-3.7-dev libclang-3.7-dev python zlib1g-dev libelf-dev

RUN git clone https://github.com/iovisor/bcc.git 

# RUN mkdir bcc/build; cd bcc/build ; \
#       cmake .. -DCMAKE_INSTALL_PREFIX=/usr ; \
#       make ; \
#       make install 


# CMD python --version
CMD lsb_release -a 
