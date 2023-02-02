package main

import (
	"fmt"
	"nostr-go/nip/nip06"
	"nostr-go/nip/nip19"
)

func main() {
	fmt.Println("start generate private key")
	privateKey, err := nip06.KeyGen()
	if err != nil {
		panic(err)
	}
	fmt.Printf("private key is %s \n", privateKey)

	PubKey, err := nip06.GetPubKeyFromPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("public key is %s \n", PubKey)

	privateKeyBech32, err := nip19.EncodePrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("private key bech32-formatted is %s \n", privateKeyBech32)

	PubKeyBech32, err := nip19.EncodePublicKey(PubKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("public key bech32-formatted is %s \n", PubKeyBech32)
}
