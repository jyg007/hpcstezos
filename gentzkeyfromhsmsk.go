package main

import (
	"fmt"
	"os"    
	"encoding/hex"
	"encoding/asn1"
	"errors"
)

// ecPrivateKey is an ASN.1 encoded EC key defined here:
// https://tools.ietf.org/html/rfc5915
type ecKeyType struct {
	Algo asn1.ObjectIdentifier 
	Curve asn1.ObjectIdentifier
}

// pkcs8PrivateKey is an ASN.1 encoded EC key defined here:
// https://tools.ietf.org/html/rfc5208
type pkcs8PrivateKey struct {
	Version             int
    KeyType				ecKeyType
	PrivateKey          []byte
}

type IBMPrivateKey struct {
	Version     int
    SK          []byte
    PK			asn1.BitString `asn1:"optional,explicit,tag:1"`
}

func main() {

	//fournir l output de ./uncipherseed <BLOB>
	sk , _ := hex.DecodeString(os.Args[1])

	var privKey pkcs8PrivateKey
	var rest []byte
	var err error

	if rest, err = asn1.Unmarshal(sk, &privKey); err != nil {
        errors.New("error")
        return
    } else if len(rest) != 0 {
        errors.New("Trailing data after ASN.1 of private key")
        return
    }

    var  SK IBMPrivateKey

    if rest, err = asn1.Unmarshal(privKey.PrivateKey, &SK); err != nil {
        errors.New("error")
        return
    } else if len(rest) != 0 {
        errors.New("Trailing data after ASN.1 of private key")
        return
    }

    if privKey.KeyType.Curve.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7} )  {
    	fmt.Println("tz3")
    	fmt.Println("Tezos Public Hash Key :", getTzPublicKeyHash(&asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},getCompressedPubkey(SK.PK.Bytes)))
        fmt.Println("Tezos Public Key      :", getTzPublicKey(&asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},getCompressedPubkey(SK.PK.Bytes)))
		fmt.Println("Tezos Secret Key      :", getTzSecretKey(&asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},SK.SK))
    } else if privKey.KeyType.Curve.Equal(asn1.ObjectIdentifier{1, 3, 101, 112} ) {
    	fmt.Println("tz1")
    	fmt.Println("Tezos Public Hash Key :", getTzPublicKeyHash(&asn1.ObjectIdentifier{1, 3, 101, 112},SK.PK.Bytes))
        fmt.Println("Tezos Public Key      :", getTzPublicKey(&asn1.ObjectIdentifier{1, 3, 101, 112},SK.PK.Bytes))
		fmt.Println("Tezos Secret Key      :", getTzSecretKey(&asn1.ObjectIdentifier{1, 3, 101, 112},SK.SK))
    } else if privKey.KeyType.Curve.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 10} ) {
    	fmt.Println("tz2")
    	fmt.Println("Tezos Public Hash Key :", getTzPublicKeyHash(&asn1.ObjectIdentifier{1, 3, 132, 0, 10},getCompressedPubkey(SK.PK.Bytes)))
        fmt.Println("Tezos Public Key      :", getTzPublicKey(&asn1.ObjectIdentifier{1, 3, 132, 0, 10},getCompressedPubkey(SK.PK.Bytes)))
		fmt.Println("Tezos Secret Key      :", getTzSecretKey(&asn1.ObjectIdentifier{1, 3, 132, 0, 10},SK.SK))
    }
}