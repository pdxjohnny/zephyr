# Usage:
# docker build -f scripts/docker/Dockerfile -t z .
# docker run --rm -ti -v $ZEPHYR_BASE:/home/user/zephyr -w /home/user/zephyr/tests/net/dhcpv4 z bash -c 'export CLANG_ROOT=/usr && export ZEPHYR_TOOLCHAIN_VARIANT=llvm && export CC=clang && export CXX=clang++ && rm -rf build/ && mkdir build/ && cd build && cmake -GNinja -DBOARD=native_posix -DCONFIG_ASAN=y -DCONFIG_NO_OPTIMIZATIONS=y .. && ninja clean && ninja'
FROM ubuntu:18.04

ARG ZSDK_VERSION
ENV ZSDK_VERSION ${ZSDK_VERSION:-0.10.0}

# Deps
RUN apt-get -y update && \
  apt-get -y upgrade && \
  apt-get -y install --no-install-recommends \
    apt-transport-https ca-certificates gnupg software-properties-common wget \
    git cmake ninja-build gperf \
    ccache dfu-util device-tree-compiler wget \
    python3-pip python3-setuptools python3-wheel xz-utils file make clang \
    gcc-multilib && \
  update-alternatives --set cc /usr/bin/clang && \
  update-alternatives --set c++ /usr/bin/clang++

# cmake
RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc \
    2>/dev/null | apt-key add - && \
  apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main' && \
  apt-get update && \
  apt-get -y install kitware-archive-keyring && \
  apt-key --keyring /etc/apt/trusted.gpg del C1F34CDD40CD72DA && \
  apt-get -y install cmake && \
  wget "https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v${ZSDK_VERSION}/zephyr-sdk-${ZSDK_VERSION}-setup.run" && \
  sh "zephyr-sdk-${ZSDK_VERSION}-setup.run" && \
  rm "zephyr-sdk-${ZSDK_VERSION}-setup.run" && \
  useradd -m user && \
  echo 'user   ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

COPY ./scripts/requirements.txt /home/user/zephyr/scripts/requirements.txt

RUN chown -R user:user /home/user

USER user
WORKDIR /home/user

RUN echo 'export PATH=$PWD/.local/bin:$PATH' >> $HOME/.zephyrrc && \
  pip3 install --user -r $HOME/zephyr/scripts/requirements.txt && \
  echo 'export ZEPHYR_BASE=$HOME/zephyr' | \
    tee -a $HOME/.zephyrrc && \
  echo 'export ZEPHYR_TOOLCHAIN_VARIANT=zephyr' | \
    tee -a $HOME/.zephyrrc && \
  echo 'export ZEPHYR_SDK_INSTALL_DIR=/opt/zephyr-sdk' | \
    tee -a $HOME/.zephyrrc && \
  echo 'source $HOME/zephyr/zephyr-env.sh' >> $HOME/.bashrc.new && \
  cat $HOME/.bashrc >> $HOME/.bashrc.new && \
  mv $HOME/.bashrc.new $HOME/.bashrc

ENTRYPOINT ["/home/user/zephyr/scripts/docker/entrypoint.sh"]
CMD ["/bin/bash"]
