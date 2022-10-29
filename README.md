Installation:

go mod init
go mod tidy


Original procedure

createtezos
openssl ec -inform DER -in  pubkey.der -outform PEM -out pubkey.pem -pubin
./key-encoder pubkey.pem 
