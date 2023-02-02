package nip19

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcutil/bech32"
)

type ProfilePointer struct {
	PublicKey string
	Relays    []string
}

type EventPointer struct {
	ID     string
	Relays []string
}

func Decode(bech32string string) (prefix string, value any, err error) {
	prefix, bits5, err := bech32.Decode(bech32string)
	if err != nil {
		return "", nil, err
	}

	data, err := bech32.ConvertBits(bits5, 5, 8, false)
	if err != nil {
		return prefix, nil, fmt.Errorf("failed translating data into 8 bits: %s", err.Error())
	}

	switch prefix {
	case "npub", "nsec", "note":
		if len(data) < 32 {
			return prefix, nil, fmt.Errorf("data is less than 32 bytes (%d)", len(data))
		}

		return prefix, hex.EncodeToString(data[0:32]), nil
	case "nprofile":
		var result ProfilePointer
		curr := 0
		for {
			t, v := readTLVEntry(data[curr:])
			if v == nil {
				if result.PublicKey == "" {
					return prefix, result, fmt.Errorf("no pubkey found for nprofile")
				}

				return prefix, result, nil
			}

			switch t {
			case TLVDefault:
				result.PublicKey = hex.EncodeToString(v)
			case TLVRelay:
				result.Relays = append(result.Relays, string(v))
			default:
				// ignore
			}

			curr = curr + 2 + len(v)
		}
	case "nevent":
		var result EventPointer
		curr := 0
		for {
			t, v := readTLVEntry(data[curr:])
			if v == nil {
				// end here
				if result.ID == "" {
					return prefix, result, fmt.Errorf("no id found for nevent")
				}

				return prefix, result, nil
			}

			switch t {
			case TLVDefault:
				result.ID = hex.EncodeToString(v)
			case TLVRelay:
				result.Relays = append(result.Relays, string(v))
			default:
				// ignore
			}

			curr = curr + 2 + len(v)
		}
	}

	return prefix, data, fmt.Errorf("unknown tag %s", prefix)
}

func EncodePrivateKey(privateKeyHex string) (string, error) {
	b, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key hex: %w", err)
	}

	bits5, err := bech32.ConvertBits(b, 8, 5, true)
	if err != nil {
		return "", err
	}

	return bech32.Encode("nsec", bits5)
}

func EncodePublicKey(publicKeyHex string) (string, error) {
	b, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key hex: %w", err)
	}

	bits5, err := bech32.ConvertBits(b, 8, 5, true)
	if err != nil {
		return "", err
	}

	return bech32.Encode("npub", bits5)
}

func EncodeNote(eventIdHex string) (string, error) {
	b, err := hex.DecodeString(eventIdHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode event id hex: %w", err)
	}

	bits5, err := bech32.ConvertBits(b, 8, 5, true)
	if err != nil {
		return "", err
	}

	return bech32.Encode("note", bits5)
}

func EncodeProfile(publicKeyHex string, relays []string) (string, error) {
	buf := &bytes.Buffer{}
	pubkey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid pubkey '%s': %w", publicKeyHex, err)
	}
	writeTLVEntry(buf, TLVDefault, pubkey)

	for _, url := range relays {
		writeTLVEntry(buf, TLVRelay, []byte(url))
	}

	bits5, err := bech32.ConvertBits(buf.Bytes(), 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}

	return bech32.Encode("nprofile", bits5)
}

func EncodeEvent(eventIdHex string, relays []string) (string, error) {
	buf := &bytes.Buffer{}
	pubkey, err := hex.DecodeString(eventIdHex)
	if err != nil {
		return "", fmt.Errorf("invalid id '%s': %w", eventIdHex, err)
	}
	writeTLVEntry(buf, TLVDefault, pubkey)

	for _, url := range relays {
		writeTLVEntry(buf, TLVRelay, []byte(url))
	}

	bits5, err := bech32.ConvertBits(buf.Bytes(), 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}

	return bech32.Encode("nevent", bits5)
}

const (
	TLVDefault uint8 = 0
	TLVRelay   uint8 = 1
)

func readTLVEntry(data []byte) (typ uint8, value []byte) {
	if len(data) < 2 {
		return 0, nil
	}

	typ = data[0]
	length := int(data[1])
	value = data[2 : 2+length]
	return
}

func writeTLVEntry(buf *bytes.Buffer, typ uint8, value []byte) {
	length := len(value)
	buf.WriteByte(typ)
	buf.WriteByte(uint8(length))
	buf.Write(value)
}
