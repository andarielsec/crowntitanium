pip3 install sympy

1. generate keys
python3 src/gen_key.py -pub key.pub -pri key.priv

2. encrypt message
python3 src/encode -pub key.pub -m message.txt -o message.ntru

3. decrypt message
pyhton3 src/decrypt -priv key.priv -m message.ntru -o message.txt.new
