# AES-128 encryption with Diffie-Hellman algorythm for key exchange
Simple implemention of AES-128 with Diffie-Hellman algorythm for key exchange between client and server (socket)

## Getting Started
The program require some initial paramaters which can be produced by Openssl

### Prerequisites
Install Openssl from [here](https://www.openssl.org/source/)

then install pycrypto:
```
pip install pycryptodome
```

## Running the tests
### produce initial parameters with open ssl
with this command in Openssl, two public parameters for DH algorithm will produce and with next command we can see them.
```
dhparam -out dhp.pem 128
pkeyparam -in dhp.pem -text
```
then we can create private key for both sides and see the private keys
```
genpkey -paramfile dhp.pem -out dhkey_client.pem
genpkey -paramfile dhp.pem -out dhkey_server.pem
pkey -in dhkey_client.pem -text -noout
pkey -in dhkey_server.pem -text -noout
```
