package main

import (
	"bytes"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	t.Run("generates a valid key", func(t *testing.T) {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey() failed: %v", err)
		}
		if key == nil {
			t.Fatal("GenerateKey() returned a nil key")
		}
		if len(key) != 64 {
			t.Errorf("GenerateKey() returned a key of length %d, want 64", len(key))
		}
	})

	t.Run("generates different keys on subsequent calls", func(t *testing.T) {
		key1, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey() failed on first call: %v", err)
		}
		key2, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey() failed on second call: %v", err)
		}
		if bytes.Equal(key1, key2) {
			t.Error("GenerateKey() returned the same key on subsequent calls, suggesting a lack of randomness")
		}
	})
}

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key for testing: %v", err)
	}
	plaintext := []byte("this is a secret message that needs to be kept safe")

	t.Run("Successful encryption and decryption roundtrip", func(t *testing.T) {
		ciphertext, err := Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Encrypt() failed: %v", err)
		}
		if ciphertext == nil {
			t.Fatal("Encrypt() returned nil ciphertext")
		}
		if bytes.Equal(plaintext, ciphertext) {
			t.Error("Encrypt() returned ciphertext that is identical to the plaintext")
		}

		decrypted, err := Decrypt(ciphertext, key)
		if err != nil {
			t.Fatalf("Decrypt() failed: %v", err)
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Decrypt() returned %q, want %q", decrypted, plaintext)
		}
	})

	t.Run("Fails with invalid key length", func(t *testing.T) {
		invalidKey := []byte("this key is definitely not 64 bytes long")
		_, err := Encrypt(plaintext, invalidKey)
		if err == nil {
			t.Error("Encrypt() should have failed with an invalid key length, but it did not")
		}

		// We don't have valid ciphertext for an invalid key, but we can test Decrypt with it
		_, err = Decrypt([]byte("some ciphertext"), invalidKey)
		if err == nil {
			t.Error("Decrypt() should have failed with an invalid key length, but it did not")
		}
	})

	t.Run("Fails decryption with wrong key", func(t *testing.T) {
		wrongKey, err := GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate wrongKey: %v", err)
		}

		ciphertext, err := Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Encrypt() failed: %v", err)
		}

		_, err = Decrypt(ciphertext, wrongKey)
		if err == nil {
			t.Error("Decrypt() should have failed when using the wrong key, but it did not")
		}
	})

	t.Run("Fails decryption with corrupted ciphertext", func(t *testing.T) {
		ciphertext, err := Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Encrypt() failed: %v", err)
		}

		// Corrupt the ciphertext by flipping some bits
		if len(ciphertext) > 0 {
			ciphertext[0] ^= 0xff // Flip all bits of the first byte
		} else {
			t.Skip("Ciphertext is empty, cannot corrupt")
		}

		_, err = Decrypt(ciphertext, key)
		if err == nil {
			t.Error("Decrypt() should have failed with corrupted ciphertext, but it did not")
		}
	})
}
