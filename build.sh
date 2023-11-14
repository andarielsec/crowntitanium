if command -v g++ automake python3 python3-pip build-essential libssl-dev make &> /dev/null; then
    echo ""
else
    apt-get update
    apt-get install g++ automake python3 python3-pip build-essential libssl-dev make -y
    pip3 install sympy
fi

g++ c1-aes256/aes256.cpp -o bin/c1
gcc ./c2-CAMELLIA-POLY/cryptolandi.c -o bin/c2  -lssl -lcrypto

cd c4-kyber-CRYSTAL/kyber/ref
make shared
cp *.so /usr/local/lib
cd ../..
./bootstrap.sh
./configure --prefix=/usr/local/lib
make -j
make install
cp kybertest_keygen ../bin/c4-keygen
cp kybertest_encrypt ../bin/c4-encrypt
cp kybertest_decrypt ../bin/c4-decrypt

echo ""
echo "installed everything."
echo ""
