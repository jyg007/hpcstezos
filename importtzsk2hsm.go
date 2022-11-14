// Use this program to create a grep11 key blob from a clear text b58 Tz secret key

package main

import (
	"context"
	"fmt"
	"os"    
	"crypto/ed25519"

	"hpcstezos/ep11"
	"hpcstezos/grpc"

	"encoding/asn1"
	"bytes"

	"crypto/ecdsa"
  "crypto/elliptic"
  "github.com/btcsuite/btcutil/base58"
  "math/big"
  "github.com/decred/dcrd/dcrec/secp256k1"
)

var cryptoClient grep11.CryptoClient

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

	// Input takes a b58 Tezos secret key
	decoded , _ ,err := base58.CheckDecode(os.Args[1])  //version second argument

	if err != nil {
		fmt.Println(err)
		return
	}

	var skBytes []byte

   // if (version == 13) {
    	//fmt.Println("Seed")
		
		// Show the decoded data.
		
		//fmt.Println("Version Byte:", version)

		var sk []byte
 		var asn1k []byte
 		var privKey pkcs8PrivateKey

    seed := decoded[3:]
    //prefix:=decoded[0:3]
		//fmt.Printf("Decoded data: %x\n", seed)
 		
		if bytes.Equal([]byte(os.Args[1])[0:4],[]byte("edsk")) {
			//Assume this is a tz1 and a seed.  Could be wrong.  Test the len !
			//fmt.Println("tz1")

	    	sk=ed25519.NewKeyFromSeed(seed) 

	    	fmt.Println("Tezos Public Hash Key  :",getTzPublicKeyHash(&asn1.ObjectIdentifier{1, 3, 101, 112},sk[32:]))
        	fmt.Println("Tezos Public Key       :",getTzPublicKey(&asn1.ObjectIdentifier{1, 3, 101, 112},sk[32:]))

	    	k := IBMPrivateKey{
	    		Version: 1,
	    		SK: seed,
	    		PK: asn1.BitString{Bytes: sk[32:],BitLength: 256},    
    		}

	    	asn1k,err = asn1.Marshal(k)
	 	    if err != nil {
	    		fmt.Print(err)
	    		return
	    	}

	    	privKey = pkcs8PrivateKey{
	    		Version: 0,
	    		KeyType: ecKeyType{Algo: asn1.ObjectIdentifier{1, 2, 840, 10045, 2,1 }, Curve: asn1.ObjectIdentifier{1, 3, 101, 112} },
				PrivateKey:    asn1k,
			}
		}  else if bytes.Equal([]byte(os.Args[1])[0:4],[]byte("p2sk")) 	{
			//fmt.Println("tz3")

			priv := new(ecdsa.PrivateKey)
			priv.PublicKey.Curve=elliptic.P256() 
			priv.D = new(big.Int)
			priv.D.SetBytes(seed)
			priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(seed)
			pk := elliptic.Marshal(elliptic.P256(),priv.PublicKey.X,priv.PublicKey.Y)

			fmt.Println("Tezos Public Hash Key  :",getTzPublicKeyHash(&asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},getCompressedPubkey(pk)))
			fmt.Println("Tezos Public Key       :",getTzPublicKey(&asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},getCompressedPubkey(pk)))			
			
			k := IBMPrivateKey{
    		Version: 1,
    		SK: seed,
    		PK: asn1.BitString{Bytes: pk,BitLength: 8*len(pk)},    
    	}
    	asn1k,err = asn1.Marshal(k)
    	if err != nil {
	    	fmt.Println(err)
	    	return
	    }
	    privKey = pkcs8PrivateKey{
	    	Version: 0,
	    	KeyType: ecKeyType{Algo: asn1.ObjectIdentifier{1, 2, 840, 10045, 2,1 }, Curve: asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7} },
				PrivateKey:    asn1k,
			}

		}  else if bytes.Equal([]byte(os.Args[1])[0:4],[]byte("spsk")) 	{
			//fmt.Println("tz2")

			_ , pk := secp256k1.PrivKeyFromBytes(seed)

			fmt.Println("Tezos Public Hash Key  :",getTzPublicKeyHash(&asn1.ObjectIdentifier{1, 3, 132, 0, 10},pk.SerializeCompressed()))
			fmt.Println("Tezos Public Key       :",getTzPublicKey(&asn1.ObjectIdentifier{1, 3, 132, 0, 10},pk.SerializeCompressed()))			
			
			k := IBMPrivateKey{
    		Version: 1,
    		SK: seed,
    		PK: asn1.BitString{Bytes: pk.SerializeUncompressed(),BitLength: 8*len(pk.SerializeUncompressed())},    
    	}
    	asn1k,err = asn1.Marshal(k)
    	if err != nil {
	    	fmt.Print(err)
	    	return
	    }
	    privKey = pkcs8PrivateKey{
	    	Version: 0,
	    	KeyType: ecKeyType{Algo: asn1.ObjectIdentifier{1, 2, 840, 10045, 2,1 }, Curve: asn1.ObjectIdentifier{1, 3, 132, 0, 10} },
			  PrivateKey:    asn1k,
			}

		}  	
  
    skBytes,err =asn1.Marshal(privKey)
    if err != nil {
    	fmt.Print(err)
    }
  //  }
    
    cryptoClient = getGrep11Server()
   	defer disconnectGrep11Server() 

   	// Create an ephemeral AES key
	aesKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN:   256 / 8,
		ep11.CKA_WRAP:        true,
		ep11.CKA_UNWRAP:      true,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: true,
		ep11.CKA_TOKEN:       true,
	}

	aesGenerateKeyRequest := &grep11.GenerateKeyRequest{
		Mech:     &grep11.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: AttributeMap(aesKeyTemplate),
	}
	aesGenerateKeyStatus, err := cryptoClient.GenerateKey(context.Background(), aesGenerateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey error: %s", err))
	}

	iv := []byte("0123456789abcdef")

	// Encrypt the seed using the ephemeral key
	encryptSingleRequest := &grep11.EncryptSingleRequest{
		Mech:  &grep11.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: &grep11.Mechanism_ParameterB{ParameterB: iv[:]}},
		Key:   aesGenerateKeyStatus.KeyBytes,
		Plain: skBytes,
	}
	encryptSingleResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("Encrypt secret error: %s", err))
	}

	// Uncrypt the ciphered seed to get the key blob 
	unnwrapKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:       ep11.CKO_PRIVATE_KEY,
		ep11.CKA_KEY_TYPE:    ep11.CKK_EC,
		ep11.CKA_VALUE_LEN:   len(skBytes),
		ep11.CKA_WRAP:        false,
		ep11.CKA_UNWRAP:      true,
		ep11.CKA_SIGN:        true,
		ep11.CKA_VERIFY:      false,
		ep11.CKA_DERIVE:      true,
		ep11.CKA_EXTRACTABLE: true,  // to be changed to false for a real case !!!
	}

	unwrapRequest := &grep11.UnwrapKeyRequest{
		Wrapped:  encryptSingleResponse.Ciphered,
		KeK:      aesGenerateKeyStatus.KeyBytes,
		Mech:     &grep11.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: &grep11.Mechanism_ParameterB{ParameterB: iv[:]}},
		Template: AttributeMap(unnwrapKeyTemplate),
	}

	unWrappedResponse, err := cryptoClient.UnwrapKey(context.Background(), unwrapRequest)
	if err != nil {
		panic(fmt.Errorf("Unwrap key error: %s", err))
	}

  fmt.Printf("Tezos Private Key Blob : %x\n",unWrappedResponse.Unwrapped.KeyBlobs[0])

}
