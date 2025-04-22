package services

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const testKey = `{
    "kty": "EC",
    "d": "EZZyzkFSE8bkfC0RtEHyQbhRCqWMuE3xGGkHf8oaOMc",
    "crv": "P-256",
    "x": "SbSvVMXbCn6geaL7QusrmBMgSonD-orUd5CTtkKKPfA",
    "y": "u3aswKUlUbxfcQqKIFIdjivfRnIDkw67I8uCFR686c0"
}`

func generateKey() (jwk.Key, jwk.Key) {
	privateKey, err := jwk.ParseKey([]byte(testKey))
	if err != nil {
		log.Info("Failed to parse JWK: ", err)
	}

	publicKey, err := jwk.PublicKeyOf(privateKey)
	if err != nil {
		log.Info("Failed to get public Key: ", err)
	}
	return privateKey, publicKey
}

func TestEncryption(t *testing.T) {
	/*prvKey, pubKey := generateKey()

	credential := entity.CredentialResponseObject{
		Format:        "jwt_vc_json",
		Credential:    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImlkIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzM3MzIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiaHR0cHM6Ly9leGFtcGxlLmVkdS9pc3N1ZXJzLzU2NTA0OSIsImlzc3VhbmNlRGF0ZSI6IjIwMTAtMDEtMDFUMDA6MDA6MDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMifX19LCJpc3MiOiJodHRwczovL2V4YW1wbGUuZWR1L2lzc3VlcnMvNTY1MDQ5IiwibmJmIjoxMjYyMzA0MDAwLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSJ9.z5vgMTK1nfizNCg5N-niCOL3WUIAL7nXy-nGhDZYO_-PNGeE-0djCpWAMH8fD8eWSID5PfkPBYkx_dfLJnQ7NA",
		TransactionID: "8xLOxBtZp8",
	}

	encrypt := EncryptResponse(credential, pubKey)

	decrypt, err := jwt.DecryptJweMessage(encrypt, jwe.WithKey(jwa.ECDH_ES_A256KW, prvKey))
	if err != nil {
		t.Error(err)
	}

	serialize, err := json.Marshal(credential)
	if err != nil {
		t.Error(err)
	}

	require.Equal(t, serialize, decrypt)*/
}
