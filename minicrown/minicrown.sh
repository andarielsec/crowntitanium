echo "Enter filepath to encrypt: "
echo ""
read filepath
$filename = $(basename -- "$filepath")

./bin/minicrown_keygen -o /tmp/$filename-c1
./bin/minicrown_keygen -o /tmp/$filename-c2

echo "Generated keys: "
echo ""
echo "!SAVE THESE FILES SECURELY!"
ls /tmp/$filename-*

echo "Encrypting file using minicrown c1: kyber-DILITHIUM CRYSTALS"
echo ""
cat $filepath | bin/minicrown_encrypt -r /tmp/$filename-c1.pub > $filename.minicrown
echo ""
echo ""
echo "Encrypting public key file of c1 with minicrown c2: kyber-DILITHIUM CRYSTALS"
echo ""
cat /tmp/$filename-c1.priv | bin/minicrown_encrypt -r /tmp/$filename-c2.pub >> /tmp/$filename-c1.priv
# Decrypt 2-Layered Kyber-DILITHIUM and CRYSTALS (MINICROWN)
# cat /tmp/$filename-c1.priv | bin/minicrown_decrypt -k /tmp/$filename-c2.priv >> /tmp/$filename-c1.priv
# $filename.minicrown | bin/minicrown_decrypt -k /tmp/$filename-c1.priv >> $filename.txt
