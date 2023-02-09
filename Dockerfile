FROM gcc:11.3.0

RUN apt-get -qq update
RUN apt-get -qq upgrade
RUN apt-get -qq install cmake

RUN dpkg --configure -a
# RUN apt-get -qq install libboost-all-dev
RUN apt-get -qq install -y libasio-dev && \ 
    apt-get -qq install -y zlib1g && \
    apt-get -qq install -y libssl-dev && \ 
    apt-get install build-essential libtcmalloc-minimal4 && \
    ln -s /usr/lib/libtcmalloc_minimal.so.4 /usr/lib/libtcmalloc_minimal.so && \ 
    cd / && \ 
    git clone https://github.com/CrowCpp/Crow.git && \
    cd Crow && \
    mkdir build && \
    cd build && \
    cmake .. -DCROW_BUILD_EXAMPLES=OFF -DCROW_BUILD_TESTS=OFF -DCROW_FEATURES="ssl;compression" && \
    make install

# RUN openssl genrsa -des3 -passout pass:x -out server.pass.key 2048 && \
#     openssl rsa -passin pass:x -in server.pass.key -out server.key && \
#     rm server.pass.key && \
#     openssl req -new -key server.key -out server.csr \
#         -subj "/C=US/ST=NY/L=NYC/O=Iyobed/OU=Iyobed Department/CN=iyobedz.com" && \
#     openssl x509 -req -days 10000 -in server.csr -signkey server.key -out server.crt


RUN git clone https://github.com/IyobedZekarias/cppAPI.git && \
    git clone https://github.com/IyobedZekarias/gmpwoop.git && \ 
    git clone https://github.com/IyobedZekarias/Crypto.git && \
    cd Crypto && make && make install && \
    cd gmpwoop && ./configure --enable-woop && make && make install

# INSTALL CRYPTO_IZ


# INSTALL GMPWOOP

RUN mkdir cppAPI/build && \
    cd cppAPI/build && \
    cmake .. && make

ENV LD_LIBRARY_PATH=/usr/local/lib




    
# ADD ./usr/include /usr/local/include
# VOLUME ./ $HOME/cppAPI/
# RUN dpkg-deb -R $HOME/cppAPI/crow-v1.0+5.deb $HOME/cppAPI/
# sudo docker run -v ~/cppAPI:/usr/src/cppAPI -p 18080:443 -e PORT=443 -ti crypto:latest /usr/src/cppAPI/build/cppAPI


# sudo docker run -v ~/cppAPI:/usr/src/cppAPI -ti crypto:latest bash

# sudo docker run -v ~/cppAPI:/usr/src/cppAPI -p $PORT:443 -e PORT=443 -ti crypto:latest /bin/bash -c "cd usr/src/cppAPI/build; make; ./cppAPI"


# sudo docker build --no-cache -t crypto .
# sudo docker buildx build --platform=linux/amd64 -t crypto .

# sudo docker run -p $PORT:443 -e PORT=443 -ti crypto:latest /cppAPI/build/cppAPI