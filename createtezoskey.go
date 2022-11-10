package main

import (
	"context"
	"fmt"

	"encoding/hex"

	"hpcstezos/ep11"
	pb "hpcstezos/grpc"

	"encoding/asn1"
	"os"

	"crypto/x509/pkix"
	"errors"
)

// publicKey is an ASN.1 encoded Subject Public Key Info, defined here:
// https://tools.ietf.org/html/rfc5280#section-4.1.2.7
type subjectPublicKeyInfo struct {
        Algorithm pkix.AlgorithmIdentifier
        PublicKey asn1.BitString
}


var cryptoClient pb.CryptoClient

func main() {

        cryptoClient = getGrep11Server()
   	defer disconnectGrep11Server() 

        var err error
        var ecParameters []byte

        if (os.Args[1] == "tz3") {
                ecParameters, err = asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})  //prime256v1
        }
        if (os.Args[1] == "tz1") {
                ecParameters, err = asn1.Marshal(asn1.ObjectIdentifier{1, 3, 101, 112})  //Ed25519
        }

        if err != nil {
                panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
        }

        publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VERIFY:         true,
		ep11.CKA_EC_PARAMS: ecParameters,
        }
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:     true,
		ep11.CKA_SENSITIVE:   true,
		ep11.CKA_SIGN:     true,
		ep11.CKA_EXTRACTABLE: true,  // à changer pour la prod !
	}
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: AttributeMap(privateKeyTemplate),
	}
	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

        fmt.Printf("%x\n\n",generateKeyPairResponse.PrivKeyBytes)
        //openssl ec -inform DER -in  pubkey.der -outform PEM -out pubkey.pem -pubin

        // ParseAsn1Pubkey parses DER encoded bytes using the ASN.1
        // Public Key structure and returns our public key material
        // Compare to: x509.ParsePKIXPublicKey()

        var pubKey subjectPublicKeyInfo
        // Parse the public key
        if rest, err := asn1.Unmarshal(generateKeyPairResponse.PubKey.Attributes[ep11.CKA_PUBLIC_KEY_INFO].GetAttributeB(), &pubKey); err != nil {
                errors.New("error")
        } else if len(rest) != 0 {
                errors.New("x509: trailing data after ASN.1 of public-key")
        }
        // Parse the algo
        paramsData := pubKey.Algorithm.Parameters.FullBytes
        namedCurveOID := new(asn1.ObjectIdentifier)
        asn1.Unmarshal(paramsData, namedCurveOID)

        var PublicKey []byte
        if (os.Args[1] == "tz3") {
                PublicKey = getCompressedPubkey(pubKey.PublicKey.Bytes)
        }
        if (os.Args[1] == "tz1") {
                PublicKey = pubKey.PublicKey.Bytes
        }
        
        fmt.Println(getTzPublicKey(namedCurveOID,PublicKey))

        pkh:=getTzPublicKeyHash(namedCurveOID,PublicKey)
        fmt.Println(pkh)

        fsk,_ := os.Create(pkh+".sk.hex")
        fsk.Write([]byte(hex.EncodeToString(generateKeyPairResponse.PrivKey.KeyBlobs[0])))
        defer fsk.Close()

        f, _ :=os.Create(pkh+".der")
        f.Write(generateKeyPairResponse.PubKey.Attributes[ep11.CKA_PUBLIC_KEY_INFO].GetAttributeB())
        defer f.Close()

}
