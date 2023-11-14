cd kyber/ref
make shared
cp *.so /usr/local/lib
cd ../..
./bootstrap.sh
./configure --prefix=/usr/local/lib
make -j
make install
cp kybertest_keygen kybertest_encrypt kybertest_decrypt ../bin
