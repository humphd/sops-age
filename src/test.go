package main


import (
    cryptoaes "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "fmt"
    "strconv"
    "strings"
)

type encryptedValue struct {
	data     []byte
	iv       []byte
	tag      []byte
	datatype string
}

const nonceSize int = 32

func isEmpty(v interface{}) bool {
    if v == nil {
        return true
    }
    switch value := v.(type) {
    case string:
        return value == ""
    case int:
        return value == 0
    case float64:
        return value == 0
    case bool:
        return false
    default:
        return false
    }
}

// Cipher encrypts and decrypts data keys with AES GCM 256
type Cipher struct {}

// NewCipher is the constructor for a new Cipher object
func NewCipher() Cipher {
	return Cipher{}
}

// Encrypt takes one of (string, int, float, bool) and encrypts it with the provided key and additional auth data, returning a sops-format encrypted string.
func (c Cipher) Encrypt(plaintext interface{}, key []byte, iv []byte, additionalData string) (ciphertext string, err error) {
    if isEmpty(plaintext) {
        return "", nil
    }
	if isEmpty(plaintext) {
		return "", nil
	}
	aescipher, err := cryptoaes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("Could not initialize AES GCM encryption cipher: %s", err)
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

func parse(value string) (*encryptedValue, error) {
    if len(value) < 10 || value[:4] != "ENC[" || value[len(value)-1:] != "]" {
        return nil, fmt.Errorf("Invalid encrypted value format")
    }
    value = value[4 : len(value)-1]
    parts := strings.Split(value, ",")
    if len(parts) < 4 || parts[0] != "AES256_GCM" {
        return nil, fmt.Errorf("Invalid encrypted value format")
    }
    
    result := &encryptedValue{}
    
    for _, part := range parts[1:] {
        kv := strings.Split(part, ":")
        if len(kv) != 2 {
            continue
        }
        switch kv[0] {
        case "data":
            result.data, _ = base64.StdEncoding.DecodeString(kv[1])
        case "iv":
            result.iv, _ = base64.StdEncoding.DecodeString(kv[1])
        case "tag":
            result.tag, _ = base64.StdEncoding.DecodeString(kv[1])
        case "type":
            result.datatype = kv[1]
        }
    }
    return result, nil
}

func (c Cipher) Decrypt(ciphertext string, key []byte, additionalData string) (plaintext interface{}, err error) {
    if isEmpty(ciphertext) {
        return "", nil
    }
    encryptedValue, err := parse(ciphertext)
    if err != nil {
        return nil, err
    }
    aescipher, err := cryptoaes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCMWithNonceSize(aescipher, len(encryptedValue.iv))
    if err != nil {
        return nil, err
    }
    data := append(encryptedValue.data, encryptedValue.tag...)
    decryptedBytes, err := gcm.Open(nil, encryptedValue.iv, data, []byte(additionalData))
    if err != nil {
        return nil, fmt.Errorf("Could not decrypt with AES_GCM: %s", err)
    }
    decryptedValue := string(decryptedBytes)
    switch encryptedValue.datatype {
    case "str":
        plaintext = decryptedValue
    case "int":
        plaintext, err = strconv.Atoi(decryptedValue)
    case "float":
        plaintext, err = strconv.ParseFloat(decryptedValue, 64)
    case "bytes":
        plaintext = decryptedBytes
    case "bool":
        plaintext, err = strconv.ParseBool(decryptedValue)
    default:
        return nil, fmt.Errorf("Unknown datatype: %s", encryptedValue.datatype)
    }
    return plaintext, err
}

func main() {
    cipher := NewCipher()
    
    // Fixed 32-byte key (AES-256)
    key := []byte("12345678901234567890123456789012")
    
    // Fixed 32-byte IV/nonce
    iv := []byte("12345678901234567890123456789012")
    
    encrypted, err := cipher.Encrypt("Hello, World!", key, iv, "some-auth-data")
    if err != nil {
        fmt.Printf("Error encrypting: %v\n", err)
        return
    }
    
    fmt.Printf("Encrypted: %s\n", encrypted)
    
    decrypted, err := cipher.Decrypt(encrypted, key, "some-auth-data")
    if err != nil {
        fmt.Printf("Error decrypting: %v\n", err)
        return
    }
    
    fmt.Printf("Decrypted: %s\n", decrypted)
}
