package main

import (
	"encoding/hex"
	"context"
	"fmt"
	"os"
	"strconv"
	 "encoding/asn1"
	 "bytes"
	 "errors"
	"hpcstezos/ep11"
	"hpcstezos/grpc"
)

var cryptoClient grep11.CryptoClient

var ecParameters []byte 

var slip10DerivType = map[string]grep11.BTCDeriveParm_BTCDeriveType{
    "PRV2PRV" :5,
    "PRV2PUB" :6,
    "PUB2PUB" :7,  // unsupported
    "MASTERK" :8,
}

type ecKeyType struct {
	Algo asn1.ObjectIdentifier 
	Curve asn1.ObjectIdentifier
}

// pkcs8PrivateKey is an ASN.1 encoded EC key defined here:
// https://tools.ietf.org/html/rfc5208
type PubKey struct {
    KeyType		ecKeyType
	Pk          asn1.BitString
}


func slip10_deriveKey(deriveType string, childKeyIndex uint64, hardened bool, baseKey []byte, chainCode []byte) ([]byte, []byte) {

	if hardened {
		childKeyIndex += 0x80000000
	}

	deriveKeyRequest := &grep11.DeriveKeyRequest{
		Mech: &grep11.Mechanism{
			Mechanism: ep11.CKM_IBM_BTC_DERIVE,
			Parameter: &grep11.Mechanism_BTCDeriveParameter{
				BTCDeriveParameter: &grep11.BTCDeriveParm{
					Type:          slip10DerivType[deriveType],
					ChildKeyIndex: childKeyIndex,
					ChainCode:     chainCode,
					Version:       1,
				},
			},
		},
		Template: AttributeMap(
			ep11.EP11Attributes{
				ep11.CKA_VERIFY:          true,
				ep11.CKA_SIGN: 	          true,
				ep11.CKA_EXTRACTABLE:     true,
				ep11.CKA_DERIVE:          true,
				ep11.CKA_KEY_TYPE:        ep11.CKK_ECDSA,
				ep11.CKA_VALUE_LEN:       (uint64)(0),
				ep11.CKA_IBM_USE_AS_DATA: true,
				ep11.CKA_EC_PARAMS:       ecParameters,
			},
		),
		BaseKey: baseKey,
	}

	deriveKeyResponse, err := cryptoClient.DeriveKey(context.Background(), deriveKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Derived Child Key request: %+v error: %s", deriveKeyRequest, err))
	}

	return deriveKeyResponse.NewKey.KeyBlobs[0], deriveKeyResponse.CheckSum
}


func main() {

    switch os.Args[1] {
    case "tz3":
        ecParameters, err = asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})  //prime256v1 
    case "tz1":
    	// attention le chemin de derivation doit tjs être durci.
        ecParameters, err = asn1.Marshal(asn1.ObjectIdentifier{1, 3, 101, 112})  //Ed25519
    case "tz2":
        ecParameters, err = asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 10})  //Secp256k1
    }


   	seed := make([]byte, hex.DecodedLen(len(os.Getenv("MASTERSEED"))))
    hex.Decode(seed, []byte(os.Getenv("MASTERSEED")))

    var Chaincode []byte
    var prevSk []byte
    var prevChaincode []byte

    path := bytes.Split([]byte(os.Args[2]),[]byte("/"))

    cryptoClient = getGrep11Server()
   	defer disconnectGrep11Server() 
 
    Sk , Chaincode := slip10_deriveKey("MASTERK", 0, false, seed,nil)
   // CheckSumHex := make([]byte, hex.EncodedLen(len(Chaincode)))
 
  	var index uint64
  	var hardened bool
    for i:=1; i<len(path); i++ {
    	if path[i][len(path[i])-1] == []byte("'")[0] {
    		hardened = true
    		index , _= strconv.ParseUint(string(path[i][:len(path[i])-1]),10,64)
    	} else {
    		hardened = false
      		index ,_ = strconv.ParseUint(string(path[i]),10,64)
    	}

   		prevSk = Sk
    	prevChaincode = Chaincode

	    Sk , Chaincode = slip10_deriveKey("PRV2PRV", index, hardened, Sk, Chaincode)   	
    }

    var pk []byte
    if len(path)>1 {
 		   pk , _ = slip10_deriveKey("PRV2PUB", index, hardened, prevSk, prevChaincode)   	
    }
 
	fmt.Printf("Secret Key Blob : %x\n",Sk)
    if len(path)>1 {

	    var PK PubKey
		var rest []byte
		var err error
		if rest, err = asn1.Unmarshal(pk, &PK); err != nil {
        	errors.New("error")
        	return
    	} else if len(rest) != 0 {
    		// EP11 specific data - to be ignored.
            //fmt.Println("Trailing data after ASN.1 of public key")  
            // fmt.Printf("\n%x\n",rest)
        	//return
    	}
    	//fmt.Printf("\n%x\n",PK.Pk.Bytes)
    	switch os.Args[1] {
        case "tz3":
        	fmt.Println("Tezos Public Hash Key :", getTzPublicKeyHash(&asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},getCompressedPubkey(PK.Pk.Bytes)))
        	fmt.Println("Tezos Public Key      :", getTzPublicKey(&asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},getCompressedPubkey(PK.Pk.Bytes)))
        case "tz1":
        	fmt.Println("Tezos Public Hash Key :", getTzPublicKeyHash(&asn1.ObjectIdentifier{1, 3, 101, 112},PK.Pk.Bytes))
        	fmt.Println("Tezos Public Key      :", getTzPublicKey(&asn1.ObjectIdentifier{1, 3, 101, 112},PK.Pk.Bytes))
        case "tz2":
        	fmt.Println("Tezos Public Hash Key :", getTzPublicKeyHash(&asn1.ObjectIdentifier{1, 3, 132, 0, 10},getCompressedPubkey(PK.Pk.Bytes)))
        	fmt.Println("Tezos Public Key      :", getTzPublicKey(&asn1.ObjectIdentifier{1, 3, 132, 0, 10},getCompressedPubkey(PK.Pk.Bytes)))
        }
    }

  }