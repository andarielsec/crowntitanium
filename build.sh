echo "building binaries for the first cipher layer: c1-aes256..."
echo ""
g++ c1-aes256/aes256.cpp -o bin/c1

echo "building binaries for the second cipher layer: c2-CAMELLIA-POLY..."
echo ""
apt-get -y install build-essential libssl-dev
gcc ./c2-CAMELLIA-POLY/cryptolandi.c -o bin/c3  -lssl -lcrypto
cp bin/c3 /usr/bin/

echo "building binaries for the third cipher layer: c3-NTRUprime..."
echo ""
apt-get install python3 -y
python3 -m pip install sympy

echo "building binaries for the fourth cipher layer: c4-kyber-CRYSTAL..."
echo ""
cd c4-kyber-CRYSTAL/kyber/ref
make shared
cp *.so /usr/local/lib
cd ..
./bootstrap.sh
./configure --prefix=/usr/local/lib
make -j
make install

echo "done installing and building all four cipher layers."
