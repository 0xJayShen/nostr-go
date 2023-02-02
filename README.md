# nostr-go

Tools for developing [Nostr](https://github.com/nostr-protocol/nostr) clients.

## Usage

### Generating a private key and a public key
```golang
package main
import (
    "fmt"
    "nostr-go/nip/nip06"
    "nostr-go/nip/nip19"
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