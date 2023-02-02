package nostr_go

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type Event struct {
	ID        string `json:"id"`
	PubKey    string `json:"pubkey"`
	Content   string `json:"content"`
	Sig       string `json:"sig"`
	Kind      int    `json:"kind"`
	Tags      Tags   `json:"tags"`
	CreatedAt int64  `json:"created_at"`

	// anything here will be mashed together with the main event object when serializing
	extra map[string]any
}

func (e *Event) GetID() (string, error) {
	res, err := e.Serialize()
	if err != nil {
		return "", err
	}

	h := sha256.Sum256(res)
	return hex.EncodeToString(h[:]), nil
}
func (e *Event) Serialize() ([]byte, error) {
	return json.Marshal([]interface{}{
		0,
		e.PubKey,
		e.CreatedAt,
		e.Kind,
		e.Tags,
		e.Content,
	})
}

func (e *Event) CheckSignature() (bool, error) {
	pk, err := hex.DecodeString(e.PubKey)
	if err != nil {
		return false, fmt.Errorf("event pubkey '%s' is invalid hex: %w", e.PubKey, err)
	}

	pubkey, err := schnorr.ParsePubKey(pk)
	if err != nil {
		return false, fmt.Errorf("event has invalid pubkey '%s': %w", e.PubKey, err)
	}

	// read signature
	s, err := hex.DecodeString(e.Sig)
	if err != nil {
		return false, fmt.Errorf("signature '%s' is invalid hex: %w", e.Sig, err)
	}

	sig, err := schnorr.ParseSignature(s)
	if err != nil {
		return false, fmt.Errorf("failed to parse signature: %w", err)
	}

	// check signature
	res, err := e.Serialize()
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256(res)
	return sig.Verify(hash[:], pubkey), nil
}

// Sign signs an event with a given privateKey
func (e *Event) Sign(privateKey string) error {
	res, err := e.Serialize()
	if err != nil {
		return err
	}

	h := sha256.Sum256(res)
	s, err := hex.DecodeString(privateKey)
	if err != nil {
		return fmt.Errorf("sign called with invalid private key '%s': %w", privateKey, err)
	}

	sk, _ := btcec.PrivKeyFromBytes(s)

	sig, err := schnorr.Sign(sk, h[:])
	if err != nil {
		return err
	}

	e.ID = hex.EncodeToString(h[:])
	e.Sig = hex.EncodeToString(sig.Serialize())
	return nil
}

func (e *Event) SetExtra(key string, value any) {
	if e.extra == nil {
		e.extra = make(map[string]any)
	}
	e.extra[key] = value
}

// GetExtra tries to get a value under the given key that may be present in the event object
// but is hidden in the basic type since it is out of the spec.
func (e *Event) GetExtra(key string) any {
	ival, _ := e.extra[key]
	return ival
}
func (e *Event) GetExtraString(key string) string {
	ival, ok := e.extra[key]
	if !ok {
		return ""
	}
	val, ok := ival.(string)
	if !ok {
		return ""
	}
	return val
}
func (e *Event) GetExtraNumber(key string) float64 {
	ival, ok := e.extra[key]
	if !ok {
		return 0
	}

	switch val := ival.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case int64:
		return float64(val)
	}

	return 0
}

// GetExtraBoolean is like [Event.GetExtra], but only works if the value is a boolean,
// otherwise returns the zero-value.
func (e *Event) GetExtraBoolean(key string) bool {
	ival, ok := e.extra[key]
	if !ok {
		return false
	}
	val, ok := ival.(bool)
	if !ok {
		return false
	}
	return val
}
