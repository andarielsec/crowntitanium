cd kyber/ref
make shared
cp *.so /usr/local/lib
cd ../..
./bootstrap.sh
./configure --prefix=/usr/local/lib
make -j
make install
cp minicrown_keygen minicrown_encrypt minicrown_decrypt ../bin
