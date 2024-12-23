package main


import (
	cryptoaes "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
)
import "fmt"

type encryptedValue struct {
	data     []byte
	iv       []byte
	tag      []byte
	datatype string
}

const nonceSize int = 32

type stashKey struct {
	additionalData string
	plaintext      interface{}
}

// Cipher encrypts and decrypts data keys with AES GCM 256
type Cipher struct {
	// stash is a map that stores IVs for reuse, so that the ciphertext doesn't change when decrypting and reencrypting
	// the same values.
	stash map[stashKey][]byte
}

// NewCipher is the constructor for a new Cipher object
func NewCipher() Cipher {
	return Cipher{
		stash: make(map[stashKey][]byte),
	}
}

// Encrypt takes one of (string, int, float, bool) and encrypts it with the provided key and additional auth data, returning a sops-format encrypted string.
func (c Cipher) Encrypt(plaintext interface{}, key []byte, additionalData string) (ciphertext string, err error) {
	if isEmpty(plaintext) {
		return "", nil
	}
	aescipher, err := cryptoaes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("Could not initialize AES GCM encryption cipher: %s", err)
	}
	var iv []byte
	if stash, ok := c.stash[stashKey{plaintext: plaintext, additionalData: additionalData}]; !ok {
		iv = make([]byte, nonceSize)
		_, err = rand.Read(iv)
		if err != nil {
			return "", fmt.Errorf("Could not generate random bytes for IV: %s", err)
		}
	} else {
		iv = stash
	}
	gcm, err := cipher.NewGCMWithNonceSize(aescipher, nonceSize)
	if err != nil {
		return "", fmt.Errorf("Could not create GCM: %s", err)
	}
	var plainBytes []byte
	var encryptedType string
	switch value := plaintext.(type) {
	case string:
		encryptedType = "str"
		plainBytes = []byte(value)
	case int:
		encryptedType = "int"
		plainBytes = []byte(strconv.Itoa(value))
	case float64:
		encryptedType = "float"
		// The Python version encodes floats without padding 0s after the decimal point.
		plainBytes = []byte(strconv.FormatFloat(value, 'f', -1, 64))
	case bool:
		encryptedType = "bool"
		// The Python version encodes booleans with Titlecase
		if value {
			plainBytes = []byte("True")
		} else {
			plainBytes = []byte("False")
		}
	case sops.Comment:
		encryptedType = "comment"
		plainBytes = []byte(value.Value)
	default:
		return "", fmt.Errorf("Value to encrypt has unsupported type %T", value)
	}
	out := gcm.Seal(nil, iv, plainBytes, []byte(additionalData))
	return fmt.Sprintf("ENC[AES256_GCM,data:%s,iv:%s,tag:%s,type:%s]",
		base64.StdEncoding.EncodeToString(out[:len(out)-cryptoaes.BlockSize]),
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(out[len(out)-cryptoaes.BlockSize:]),
		encryptedType), nil
}

func main() {
    fmt.Println("Hello, World!")
}