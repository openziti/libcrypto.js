FROM ubuntu:18.04

RUN apt-get update && apt-get -y install \ 
    build-essential \
    cmake \
    autoconf \
    nodejs \
    default-jre \
    libtool \
    curl \
    git-core \
    zip

RUN apt-get -y install python3.8 python3.8-dev python3.8-distutils python3.8-venv

WORKDIR /opt

RUN git clone https://github.com/emscripten-core/emsdk.git

WORKDIR /opt/emsdk

ARG EMSCRIPTEN_V

RUN git pull

# Download and install the latest SDK tools.
RUN ./emsdk install ${EMSCRIPTEN_V}

# Make the "latest" SDK "active" for the current user. (writes .emscripten file)
RUN ./emsdk activate ${EMSCRIPTEN_V}

RUN git config --global user.name 'Nobody'
RUN git config --global user.email 'nobody@nowhere.nope'

RUN mkdir /opt/openssljs

WORKDIR /opt
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

WORKDIR /opt/openssljs

ENTRYPOINT ["/opt/entrypoint.sh"]
