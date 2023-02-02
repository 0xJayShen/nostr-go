# nostr-go

Tools for developing [Nostr](https://github.com/nostr-protocol/nostr) clients.

## Usage

### Generate a private key and a public key
```go
package main
import (
    "fmt"
    "nostr-go/nips/nip06"
    "nostr-go/nips/nip19"
)

func main() {
    privateKey, _ := nip06.KeyGen()
    fmt.Printf("private key is %s \n", privateKey)
    
    PubKey, _ := nip06.GetPubKeyFromPrivateKey(privateKey)
    fmt.Printf("public key is %s \n", PubKey)
    
    privateKeyBech32, _ := nip19.EncodePrivateKey(privateKey)
    fmt.Printf("private key bech32-formatted is %s \n", privateKeyBech32)
    
    PubKeyBech32, _ := nip19.EncodePublicKey(PubKey)
    fmt.Printf("public key bech32-formatted is %s \n", PubKeyBech32)
}
```

### Create, sign and verify events
```go
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
```
