FROM gcc:11.3.0

RUN apt-get -qq update
RUN apt-get -qq upgrade
RUN apt-get -qq install cmake

RUN dpkg --configure -a
# RUN apt-get -qq install libboost-all-dev
RUN apt-get -qq install -y libasio-dev
RUN apt-get -qq install -y zlib1g
RUN apt-get -qq install -y libssl-dev
RUN apt-get install build-essential libtcmalloc-minimal4 && \
    ln -s /usr/lib/libtcmalloc_minimal.so.4 /usr/lib/libtcmalloc_minimal.so

RUN git clone https://github.com/CrowCpp/Crow.git
RUN cd Crow
RUN mkdir Crow/build
RUN cd Crow/build && cmake .. -DCROW_BUILD_EXAMPLES=OFF -DCROW_BUILD_TESTS=OFF -DCROW_FEATURES="ssl;compression"
RUN cd Crow/build && make install

# RUN openssl genrsa -des3 -passout pass:x -out server.pass.key 2048 && \
#     openssl rsa -passin pass:x -in server.pass.key -out server.key && \
#     rm server.pass.key && \
#     openssl req -new -key server.key -out server.csr \
#         -subj "/C=US/ST=NY/L=NYC/O=Iyobed/OU=Iyobed Department/CN=iyobedz.com" && \
#     openssl x509 -req -days 10000 -in server.csr -signkey server.key -out server.crt


RUN git clone --recurse-submodules -j8 https://github.com/IyobedZekarias/cppAPI.git

# INSTALL CRYPTO_IZ
RUN cd cppAPI/Crypto && make && make install

# INSTALL GMPWOOP
RUN cd cppAPI/gmpwoop && ./configure --enable-woop && make && make install

RUN mkdir cppAPI/build && \
    cd cppAPI/build && \
    cmake .. && make

ENV LD_LIBRARY_PATH=/usr/local/lib




    
# ADD ./usr/include /usr/local/include
# VOLUME ./ $HOME/cppAPI/
# RUN dpkg-deb -R $HOME/cppAPI/crow-v1.0+5.deb $HOME/cppAPI/
# sudo docker run -v ~/cppAPI:/usr/src/cppAPI -p 18080:443 -e PORT=443 -ti crypto:latest /usr/src/cppAPI/build/cppAPI


# sudo docker run -v ~/cppAPI:/usr/src/cppAPI -ti crypto:latest bash

# sudo docker run -v ~/cppAPI:/usr/src/cppAPI -ti crypto:latest /bin/bash -c "cd usr/src/cppAPI/build; make"


# sudo docker build -t crypto .
# sudo docker buildx build --platform=linux/amd64 -t crypto .

# sudo docker run -p $PORT:443 -e PORT=443 -ti crypto:latest /cppAPI/build/cppAPI