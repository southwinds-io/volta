package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
	"southwinds.dev/volta/internal/misc"
)

// EncryptWithPassphrase encrypts data using a passphrase with PBKDF2 + ChaCha20-Poly1305
func EncryptWithPassphrase(data []byte, passphrase string) ([]byte, error) {
	// Generate random salt for PBKDF2
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key using PBKDF2
	key := pbkdf2.Key([]byte(passphrase), salt, 100000, 32, sha256.New)

	// Create cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, data, nil)

	// Combine: salt + nonce + ciphertext
	result := make([]byte, len(salt)+len(nonce)+len(ciphertext))
	copy(result[:len(salt)], salt)
	copy(result[len(salt):len(salt)+len(nonce)], nonce)
	copy(result[len(salt)+len(nonce):], ciphertext)

	return result, nil
}

// DecryptWithPassphrase decrypts data using a passphrase
func DecryptWithPassphrase(encryptedData []byte, passphrase string) ([]byte, error) {
	if len(encryptedData) < 32+12 { // salt + nonce minimum
		return nil, errors.New("encrypted data too short")
	}

	// Extract components
	salt := encryptedData[:32]
	nonce := encryptedData[32:44] // ChaCha20-Poly1305 nonce is 12 bytes
	ciphertext := encryptedData[44:]

	// Derive key
	key := pbkdf2.Key([]byte(passphrase), salt, 100000, 32, sha256.New)

	// Create cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Decrypt
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// CalculateChecksum calculates SHA-256 checksum of data
func CalculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func DeriveKey(password []byte, saltEnclave *memguard.Enclave) (*memguard.LockedBuffer, error) {
	// Open the salt enclave
	saltBuffer, err := saltEnclave.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open salt enclave: %w", err)
	}
	defer saltBuffer.Destroy() // Clean up salt buffer

	// Make a copy of salt bytes to avoid issues with concurrent access
	saltBytes := make([]byte, len(saltBuffer.Bytes()))
	copy(saltBytes, saltBuffer.Bytes())
	defer memguard.WipeBytes(saltBytes)

	// Derive the key
	derivedKey := argon2.IDKey(
		password,
		saltBytes,
		misc.ArgonTime,
		misc.ArgonMemory,
		misc.ArgonThreads,
		misc.ArgonKeyLen,
	)

	// Protect the derived key immediately
	protectedKey := memguard.NewBufferFromBytes(derivedKey)

	// Wipe the unprotected derived key
	memguard.WipeBytes(derivedKey)

	return protectedKey, nil
}

// EncryptValue is a helper function to encrypt values with a key
func EncryptValue(value, key []byte) ([]byte, error) {
	// Create cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt value
	ciphertext := aead.Seal(nil, nonce, value, nil)

	// Combine nonce and ciphertext
	encrypted := make([]byte, len(nonce)+len(ciphertext))
	copy(encrypted[:len(nonce)], nonce)
	copy(encrypted[len(nonce):], ciphertext)

	return encrypted, nil
}

// DecryptValue decrypts a value using XChaCha20-Poly1305 AEAD cipher
func DecryptValue(encryptedData, key []byte) ([]byte, error) {
	// Create the AEAD cipher using the key
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Validate input
	if len(encryptedData) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("encrypted data too short")
	}

	// Extract the nonce from the beginning of the encrypted data
	nonceSize := aead.NonceSize()
	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	// Decrypt the ciphertext
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	return plaintext, nil
}

func IsWeakKey(key []byte) bool {
	if len(key) < 32 {
		return true
	}

	// Check for all zeros
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return true
	}

	// Check for all same byte
	firstByte := key[0]
	allSame := true
	for _, b := range key[1:] {
		if b != firstByte {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}

	// Basic entropy check - count unique bytes
	uniqueBytes := make(map[byte]bool)
	for _, b := range key {
		uniqueBytes[b] = true
	}

	// Should have reasonable variety (at least 16 different byte values)
	if len(uniqueBytes) < 16 {
		return true
	}

	return false
}
