1. cd kyber/ref
2. make shared
3. cp *.so /usr/local/lib
4. cd ../..
5. ./bootstrap.sh
6. ./configure --prefix=/usr/local/lib
7. make -j
8. make install

testing

1. create file secre.txt with text in it
2. kybertest_keygen -o mykey
3. cat secret.txt | kybertest_encrypt -r mykey.pub > secret.kyb
4. cat secret.kyb | kybertest_decrypt -k mykey.priv > secret.new.txt

