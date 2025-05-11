FROM ubuntu:20.04
LABEL "about"="Loris Analyzer base img"

ARG DEBIAN_FRONTEND=noninteractive
ENV IS_DOCKER="1"

RUN apt-get update && \
    apt-get -y install --no-install-suggests --no-install-recommends \
    automake \
    bison flex \
    build-essential \
    chrpath \
    git zip lz4 zsh \
    ca-certificates \
    clang clang-tools \
    wget curl vim \
    less psmisc bsdmainutils \
    libglib2.0-dev gcc-arm-none-eabi \
    libtool libtool-bin \
    apt-utils apt-transport-https ca-certificates gnupg dialog \
    libpixman-1-dev \
    gdb-multiarch qemu-utils libcapstone-dev libarchive-dev libssl-dev \
    openssh-client openssh-server net-tools htop \
    cmake ninja-build rapidjson-dev

RUN wget https://downloads.python.org/pypy/pypy3.10-v7.3.16-linux64.tar.bz2 && \
    tar xf pypy3.10-v7.3.16-linux64.tar.bz2 && \
    mv pypy3.10-v7.3.16-linux64 pypy3.10
ENV PATH="${PATH}:/pypy3.10/bin"
RUN pypy3 -m ensurepip

RUN pypy3 -m pip install angr~=9.2.102 lz4

RUN apt-get -y install --no-install-suggests --no-install-recommends \
    libc++-dev libcurl4-openssl-dev libelf-dev libffi-dev libdwarf-dev libelf-dev libwiretap-dev wireshark-dev python3-pycparser \
    protobuf-compiler protobuf-c-compiler libprotoc-dev libprotobuf-dev libprotobuf-c-dev libjsoncpp-dev

# pypanda needs the latest cffi, because $reasons
RUN pypy3 -m pip install https://foss.heptapod.net/pypy/cffi/-/archive/branch/default/cffi-branch-default.tar.gz

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y && \
    echo 'source $HOME/.cargo/env' >> $HOME/.bashrc
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /firmwire_deps

# install libosi; pypanda dependency
RUN git clone https://github.com/panda-re/libosi.git --branch 0.1.5 --single-branch libosi
WORKDIR /firmwire_deps/libosi
RUN mkdir build && cd build && cmake -GNinja .. && ninja
RUN cd build && ninja package && dpkg -i libosi-0.1.1-Linux.deb

# Install deps for Shannon Panda
COPY ./panda /firmwire_deps/panda
WORKDIR /firmwire_deps/panda
RUN rm -rf build && mkdir build

RUN cd build && ../configure --disable-werror --target-list=arm-softmmu,mipsel-softmmu \
  --cc=gcc-9 \
  --cxx=g++-9 \
  --disable-sdl \
  --disable-user \
  --disable-linux-user \
  --disable-pyperipheral3 \
  --disable-bsd-user \
  --disable-vte \
  --disable-curses \
  --disable-vnc \
  --disable-vnc-sasl \
  --disable-vnc-jpeg \
  --disable-vnc-png \
  --disable-cocoa \
  --disable-virtfs \
  --disable-xen \
  --disable-xen-pci-passthrough \
  --disable-brlapi \
  --disable-curl \
  --disable-bluez \
  --disable-kvm \
  --disable-hax \
  --disable-rdma \
  --disable-vde \
  --disable-netmap \
  --disable-linux-aio \
  --disable-cap-ng \
  --disable-attr \
  --disable-vhost-net \
  --disable-spice \
  --disable-rbd \
  --disable-gtk \
  --disable-gnutls \
  --disable-gcrypt \
  --disable-libiscsi \
  --disable-libnfs \
  --disable-smartcard \
  --disable-libusb \
  --disable-usb-redir \
  --disable-lzo \
  --disable-snappy \
  --disable-bzip2 \
  --disable-seccomp \
  --disable-coroutine-pool \
  --disable-glusterfs \
  --disable-tpm \
  --disable-libssh2 \
  --disable-numa \
  --disable-tcmalloc \
  --disable-jemalloc \
  --disable-replication \
  --disable-vhost-vsock \
  --disable-opengl \
  --disable-virglrenderer
RUN cd build && make -j `nproc`
RUN cd panda/python/core/ && pypy3 -m pip install -e .

ENV PYTHONPATH="/loris_analyzer_deps/emulator/"

COPY requirements.txt /loris_analyzer/requirements.txt
RUN pypy3 -m pip install -r /loris_analyzer/requirements.txt
ENV PYTHONPATH="${PYTHONPATH}:/loris_analyzer/"

WORKDIR /loris_analyzer
CMD [ "/bin/bash" ]
