package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"google.golang.org/protobuf/proto"

	aeadpb "github.com/tink-crypto/tink-go/v2/proto/aes_siv_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func Encrypt(data []byte, key []byte) ([]byte, error) {
	kh, err := keysetHandleFromRawKey(key)
	if err != nil {
		return nil, err
	}
	primitive, err := daead.New(kh)
	if err != nil {
		return nil, fmt.Errorf("failed to get DAEAD primitive: %w", err)
	}
	ct, err := primitive.EncryptDeterministically(data, nil)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}
	return ct, nil
}

func Decrypt(data []byte, key []byte) ([]byte, error) {
	kh, err := keysetHandleFromRawKey(key)
	if err != nil {
		return nil, err
	}
	primitive, err := daead.New(kh)
	if err != nil {
		return nil, fmt.Errorf("failed to get DAEAD primitive: %w", err)
	}
	pt, err := primitive.DecryptDeterministically(data, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return pt, nil
}

func ReadKeyFromFile(filePath string) ([]byte, error) {
	encodedKey, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(string(encodedKey))
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode key: %w", err)
	}
	if len(key) != 64 {
		return nil, fmt.Errorf("invalid key length: got %d, want 64", len(key))
	}
	return key, nil
}

func WriteKeyToFile(filePath string, key []byte) error {
	if len(key) != 64 {
		return fmt.Errorf("invalid key length: got %d, want 64", len(key))
	}
	encodedKey := base64.StdEncoding.EncodeToString(key)
	err := os.WriteFile(filePath, []byte(encodedKey), 0600)
	if err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}
	return nil
}

func GenerateKey() ([]byte, error) {
	key := make([]byte, 64)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// Helper: create a Tink keyset handle from a raw 64-byte AES256_SIV key
func keysetHandleFromRawKey(rawKey []byte) (*keyset.Handle, error) {
	if len(rawKey) != 64 {
		return nil, fmt.Errorf("invalid raw key size: got %d bytes, want 64", len(rawKey))
	}

	// 1. Create the specific AES-SIV key proto.
	keyProto := &aeadpb.AesSivKey{
		Version:  0,
		KeyValue: rawKey,
	}

	// 2. Serialize this specific key proto.
	serializedKey, err := proto.Marshal(keyProto)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key proto: %w", err)
	}

	// 3. Create the generic KeyData structure.
	keyData := &tinkpb.KeyData{
		TypeUrl:         daead.AESSIVKeyTemplate().TypeUrl,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}

	// 4. Create the Keyset structure.
	primaryKeyID := uint32(1)
	keysetProto := &tinkpb.Keyset{
		PrimaryKeyId: primaryKeyID,
		Key: []*tinkpb.Keyset_Key{
			{
				KeyData:          keyData,
				Status:           tinkpb.KeyStatusType_ENABLED,
				KeyId:            primaryKeyID,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	}

	// 5. ⭐ Marshal the entire keyset protobuf into a byte slice.
	serializedKeyset, err := proto.Marshal(keysetProto)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal keyset proto: %w", err)
	}

	// 6. ⭐ Create a binary reader from the serialized byte slice.
	reader := keyset.NewBinaryReader(bytes.NewReader(serializedKeyset))

	// 7. ⭐ Use `insecurecleartextkeyset.Read` to create the handle from the reader.
	return insecurecleartextkeyset.Read(reader)
}
