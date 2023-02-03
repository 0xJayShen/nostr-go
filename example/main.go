package main

import (
	"fmt"
	"nostr-go"
	"nostr-go/nips/nip06"
	"nostr-go/nips/nip19"
	"time"
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

	event := nostr_go.Event{
		Kind:      1,
		CreatedAt: time.Now().Unix(),
		Tags:      []nostr_go.Tag{},
		Content:   "hello",
		PubKey:    PubKey,
	}
	eventID, err := event.GetID()
	if err != nil {
		panic(err)
	}

	event.ID = eventID
	if err := event.Sign(privateKey); err != nil {
		panic(err)
	}

	ok, err := event.CheckSignature()
	if !ok || err != nil {
		fmt.Println(ok)
		panic(err)
	}
}
