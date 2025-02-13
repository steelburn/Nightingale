## Taking Image from Docker Hub for Programming language support
FROM ghcr.io/rajanagori/nightingale_programming_image:linux-amd64
## Installing tools using apt-get for web vapt
RUN \
    apt-get update -y && \
    apt-get -f --no-install-recommends install -y \
    git \
    make \
    cmake \
    bundler && \
    # Creating Directories
    cd /home &&\
    mkdir -p tools_red_teaming tools_forensics

ENV TOOLS_RED_TEAMING=/home/tools_red_teaming/
ENV TOOLS_FORENSICS=/home/tools_forensics/

## Installing Impact toolkit for Red-Team 
WORKDIR ${TOOLS_RED_TEAMING}

RUN \
    #Git clone of impacket toolkit
    git clone --depth 1 https://github.com/SecureAuthCorp/impacket.git

RUN \
    #installing impact tool
    cd impacket &&\
    python3 setup.py build &&\
    python3 setup.py install

RUN \
    # Cleaning Unwanted libraries 
    apt-get -y autoremove &&\
    apt-get -y clean &&\
    rm -rf /tmp/* &&\
    rm -rf /var/lib/apt/lists/*

WORKDIR /home