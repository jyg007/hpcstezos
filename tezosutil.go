package main

import(
	"encoding/hex"
	"encoding/asn1"
	"crypto/sha256"
    "github.com/btcsuite/btcutil/base58"
    "math/big"
    "golang.org/x/crypto/blake2b"

)

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

func getTzSecretKey(algo *asn1.ObjectIdentifier,sk []byte) string {
	if sk == nil {
		return ""
	}
	_, _, skPrefix := getTzPrefixBytes(algo)
	return b58CheckEncode(skPrefix, sk)
}