package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/pkg/errors"
	"io"
	"os"
)

const keySize = 32

// Binary format
//        8 bytes              length of encrypted key
// [length of encrypted key] [     encrypted key       ] [ cyphertext ]

func EncryptKMS(svc *kms.KMS, data []byte) ([]byte, error) {
	KMS_KEY_ID := os.Getenv("KMS_KEY_ID")
	if KMS_KEY_ID == "" {
		return nil, errors.Errorf("KMS_KEY_ID not set!")
	}

	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	res, err := svc.Encrypt(&kms.EncryptInput{
		KeyId:     &KMS_KEY_ID,
		Plaintext: key,
	})
	if err != nil {
		return nil, err
	}
	encryptedKey := res.CiphertextBlob

	lenOfEncryptedKey := uint64(len(encryptedKey))
	prefix := make([]byte, 8)
	binary.LittleEndian.PutUint64(prefix, lenOfEncryptedKey)

	ciphertext, err := EncryptWithKey(key, data)
	if err != nil {
		return nil, err
	}

	return append(append(prefix, encryptedKey...), ciphertext...), nil
}

func DecryptKMS(svc *kms.KMS, data []byte) ([]byte, error) {
	KMS_KEY_ID := os.Getenv("KMS_KEY_ID")
	if KMS_KEY_ID == "" {
		return nil, errors.Errorf("KMS_KEY_ID not set!")
	}

	lenOfEncryptedKeyBytes, data := data[:8], data[8:]
	lenOfEncryptedKey := binary.LittleEndian.Uint64(lenOfEncryptedKeyBytes)
	encryptedKey, data := data[:lenOfEncryptedKey], data[lenOfEncryptedKey:]
	res, err := svc.Decrypt(&kms.DecryptInput{
		KeyId:          &KMS_KEY_ID,
		CiphertextBlob: encryptedKey,
	})
	if err != nil {
		return nil, err
	}
	key := res.Plaintext

	plaintext, err := DecryptWithKey(key, data)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func EncryptWithKey(key, plaintext []byte) ([]byte, error) {
	// Create a new AES cipher block using the provided key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a GCM cipher block with the AES cipher and nonce
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the data
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// Append the nonce to the ciphertext
	ciphertext = append(nonce, ciphertext...)

	return ciphertext, nil

}

func DecryptWithKey(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a GCM cipher block with the AES cipher and nonce
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aesgcm.NonceSize() {
		return nil, errors.New("ciphertext is too short")
	}

	// Extract the nonce from the ciphertext
	nonce := ciphertext[:aesgcm.NonceSize()]
	ciphertext = ciphertext[aesgcm.NonceSize():]

	// Decrypt the data
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
