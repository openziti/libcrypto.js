FROM ubuntu:18.04

RUN apt-get update && apt-get -y install \ 
    build-essential \
    wget \
    autoconf \
    default-jre \
    libtool \
    curl \
    git-core \
    zip

# Install Node 14.x+
RUN curl -sL https://deb.nodesource.com/setup_14.x | bash -
RUN apt-get -y install \ 
    nodejs

RUN apt remove -y cmake
RUN apt purge -y --auto-remove cmake

RUN apt-get -y install python3.8 python3.8-dev python3.8-distutils python3.8-venv

WORKDIR /opt

RUN wget https://github.com/Kitware/CMake/releases/download/v3.25.1/cmake-3.25.1-linux-x86_64.sh 
RUN sh cmake-3.25.1-linux-x86_64.sh --prefix=/usr/local/ --exclude-subdir

RUN git clone https://github.com/emscripten-core/emsdk.git

WORKDIR /opt/emsdk

ARG EMSCRIPTEN_V

RUN git pull

# Download and install the latest SDK tools.
RUN ./emsdk install ${EMSCRIPTEN_V}

# Make the "latest" SDK "active" for the current user. (writes .emscripten file)
RUN ./emsdk activate ${EMSCRIPTEN_V}

# ##########################################################################
# #   We will use our Emscripten github fork with the EMSDK.
# #   Our Emscripten fork contains support for nested Asyncify calls.
# ##########################################################################

# # Clone+pull the latest emscripten-core/emscripten/main and set the main SDK as the currently active one
# RUN ./emsdk install sdk-upstream-main-64bit
# RUN ./emsdk activate sdk-upstream-main-64bit

# #
WORKDIR /opt/emsdk/upstream
RUN mv emscripten emscripten-orig
RUN git clone https://github.com/openziti-test-kitchen/emscripten
WORKDIR /opt/emsdk/upstream/emscripten
RUN git checkout remotes/origin/browzer-updates

# Ensure 'acorn' is installed
RUN npm install

# RUN cd emscripten/main
# # Add a git remote link to our fork of emscripten.
# RUN git remote add browzer-updates https://github.com/openziti-test-kitchen/emscripten.git
# # Obtain the changes in our fork.
# RUN git fetch browzer-updates
# # Switch the emscripten-main tool to use our branch within our fork.
# RUN git checkout -b browzer-updates --track browzer-updates/browzer-updates

RUN git config --global user.name 'Nobody'
RUN git config --global user.email 'nobody@nowhere.nope'

RUN mkdir /opt/openssljs

WORKDIR /opt
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

WORKDIR /opt/openssljs

ENTRYPOINT ["/opt/entrypoint.sh"]
