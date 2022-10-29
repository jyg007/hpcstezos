/*******************************************************************************
* Copyright 2022 IBM Corp.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

package main

import (
	"context"
	"fmt"

	"encoding/hex"

	"hpcstezos/ep11"
	pb "hpcstezos/grpc"

	"encoding/asn1"
	"os"

	"crypto/sha256"

    "golang.org/x/crypto/blake2b"

    "github.com/btcsuite/btcutil/base58"

	"crypto/x509/pkix"
	"math/big"
	"errors"

)


// publicKey is an ASN.1 encoded Subject Public Key Info, defined here:
// https://tools.ietf.org/html/rfc5280#section-4.1.2.7
type subjectPublicKeyInfo struct {
        Algorithm pkix.AlgorithmIdentifier
        PublicKey asn1.BitString
}



// Tezos Constants from:
// https://gitlab.com/tezos/tezos/blob/master/src/lib_crypto/base58.ml
const (
        /* Public Key Hashes */
        tzEd25519PublicKeyHash   = "06a19f" // tz1
        tzSecp256k1PublicKeyhash = "06a1a1" // tz2
        tzP256PublicKeyHash      = "06a1a4" // tz3

        /* Public Keys */
        tzEd25519PublicKey   = "0d0f25d9" // edpk
        tzSecp256k1PublicKey = "03fee256" // sppk
        tzP256PublicKey      = "03b28b7f" // p2pk

        /* Secret Keys */
        tzEd25519Seed        = "0d0f3a07" // edsk (54 - seed)
        tzEd25519Secret      = "2bf64e07" // edsk (98 - secret)
        tzSecp256k1SecretKey = "11a2e0c9" //spsk
        tzP256SecretKey      = "1051eebd" // p2sk

        /* Encrypted Secret Keys */
        tzEd25519EncryptedSeed        = "075a3cb329" // edesk
        tzSecp256k1EncryptedSecretKey = "09edf1ae96" // spesk
        tzP256EncryptedSecretKey      = "09303973ab" // p2esk
)

// GetTzCurveBytes used to format keys used by default client software
func getTzPrefixBytes(algo *asn1.ObjectIdentifier) ([]byte, []byte, []byte) {

  		oidPrivateKeyEd25519   := asn1.ObjectIdentifier{1, 3, 101, 112}
	    oidPrivateKeyP256      := asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
		oidPrivateKeySecp256k1 := asn1.ObjectIdentifier{1, 3, 132, 0, 10}

        if algo.Equal(oidPrivateKeySecp256k1) {
                pkh, _ := hex.DecodeString(tzSecp256k1PublicKeyhash)
                pk, _ := hex.DecodeString(tzSecp256k1PublicKey)
                sk, _ := hex.DecodeString(tzSecp256k1SecretKey)
                return pkh, pk, sk
        } else if algo.Equal(oidPrivateKeyP256) {
                pkh, _ := hex.DecodeString(tzP256PublicKeyHash)
                pk, _ := hex.DecodeString(tzP256PublicKey)
                sk, _ := hex.DecodeString(tzP256SecretKey)
                return pkh, pk, sk
        } else if algo.Equal(oidPrivateKeyEd25519) {
                pkh, _ := hex.DecodeString(tzEd25519PublicKeyHash)
                pk, _ := hex.DecodeString(tzEd25519PublicKey)
                sk, _ := hex.DecodeString(tzEd25519Secret)
                return pkh, pk, sk
        }
        return nil, nil, nil
}

func b58CheckEncode(prefix []byte, bytes []byte) string {
        message := append(prefix, bytes...)
        // SHA^2
        h := sha256.Sum256(message)
        h2 := sha256.Sum256(h[:])
        // Append first four of the hash
        finalMessage := append(message, h2[:4]...)
        // b58 encode the response
        encoded := base58.Encode(finalMessage)
        return encoded
}

func getTzPublicKey(algo *asn1.ObjectIdentifier,pubkey []byte) string {
        _, pkPrefix, _ := getTzPrefixBytes(algo)
        return b58CheckEncode(pkPrefix, pubkey)
}

func getTzPublicKeyHash(algo *asn1.ObjectIdentifier,pubkey []byte) string {
        hash, _ := blake2b.New(20, nil)
        hash.Write(pubkey)
        bytes := hash.Sum(nil)
        pkhPrefix, _, _ := getTzPrefixBytes(algo)
        return b58CheckEncode(pkhPrefix, bytes[:])
}

// GetCompressedPubkey for the given ECDSA Public Key, defined
// as the encoded LSB of Y followed by the X Coordinate of the key
func getCompressedPubkey(pubkey []byte) []byte {
        X := pubkey[1:33]
        var Y, YMod big.Int
        Y.SetBytes(pubkey[33:])

        var prefix []byte
        if YMod.Mod(&Y, big.NewInt(2)).Cmp(big.NewInt(1)) == 0 {
                prefix = []byte{0x03}
        } else {
                prefix = []byte{0x02}
        }
        compressed := append(prefix, X...)
        return compressed
}

var cryptoClient pb.CryptoClient

func main() {

    cryptoClient = getGrep11Server()
   	defer disconnectGrep11Server() 


	ecParameters, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})  //prime256v1
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
		ep11.CKA_EXTRACTABLE: false,
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

    fsk,_ := os.Create("sk.hex")
    fsk.Write([]byte(hex.EncodeToString(generateKeyPairResponse.PrivKey.KeyBlobs[0])))
    defer fsk.Close()

    f, _ :=os.Create("pubkey.der")
    f.Write(generateKeyPairResponse.PubKey.Attributes[ep11.CKA_PUBLIC_KEY_INFO].GetAttributeB())
 	defer f.Close()

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

       
    PublicKey:= getCompressedPubkey(pubKey.PublicKey.Bytes)

 	//fmt.Print(getTzPublicKey(&asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},generateKeyPairResponse.PubKey.Attributes[ep11.CKA_PUBLIC_KEY_INFO].GetAttributeB()))

	fmt.Println(getTzPublicKey(&asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},PublicKey))
	fmt.Println(getTzPublicKeyHash(&asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},PublicKey))

}
