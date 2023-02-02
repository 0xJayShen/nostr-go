package nip06

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func KeyGen() (string, error) {
	seedWords, err := GenerateSeedWords()
	if err != nil {
		return "", err
	}

	privateKey, err := PrivateKeyFromSeed(seedWords)
	if err != nil {
		return "", err
	}

	return privateKey, nil
}

func GetPubKeyFromPrivateKey(privateKey string) (string, error) {
	key, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", err
	}
	_, pubKey := btcec.PrivKeyFromBytes(key)
	return hex.EncodeToString(schnorr.SerializePubKey(pubKey)), nil
}

func GenerateSeedWords() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}

	words, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}

	return words, nil
}

func PrivateKeyFromSeed(seed string) (string, error) {
	key, err := bip32.NewMasterKey(bip39.NewSeed(seed, ""))
	if err != nil {
		return "", err
	}

	// m/44'/1237'/0'/0/0
	derivationPath := []uint32{
		bip32.FirstHardenedChild + 44,
		bip32.FirstHardenedChild + 1237,
		bip32.FirstHardenedChild + 0,
		0,
		0,
	}

	next := key
	for _, idx := range derivationPath {
		var err error
		next, err = next.NewChildKey(idx)
		if err != nil {
			return "", err
		}
	}

	return hex.EncodeToString(next.Key), nil
}
