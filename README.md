Utilisation
-----------

-> require a hpcs grep11 service to connect to (config in credential.yaml)
only support onprem .  I suggest to use native pkcs11 for IBM Cloud hpcs

create the priv key in the HSM
provide pub and tz signature.

./createtezos 
p2pk68MUzvc9TjFgGGakhAFfK8mU1Yy1ckBnjLe9anHVxdAVYWSW4zp
tz3UNncZ71gZDqj81sgR9ep4XtFi4ACsFm2T

openssl ec -inform DER -in  pubkey.der -outform PEM -out pubkey.pem -pubin
./key-encoder pubkey.pem 
read EC key
writing EC key

key-encoder pubkey.pem    // gitlab.com/polychainlabs/key-encoder
2022/10/29 11:34:14 Parsing:  pubkey.pem
Curve:  Secp256r1: 1.2.840.10045.3.1.7
Tezos Secret Key:  
Tezos Public Key:  p2pk68MUzvc9TjFgGGakhAFfK8mU1Yy1ckBnjLe9anHVxdAVYWSW4zp
Tezos Public Key Hash:  tz3UNncZ71gZDqj81sgR9ep4XtFi4ACsFm2T



Installation:
-------------

go mod init
go mod tidy


Original procedure
------------------

createtezos
openssl ec -inform DER -in  pubkey.der -outform PEM -out pubkey.pem -pubin
key-encoder pubkey.pem 
