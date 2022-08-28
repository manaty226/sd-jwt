package sdjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	issuerName = "https://example.com/issuer"
	nonce      = "XZOUco1u_gEPknxS78sWWg"
	audience   = "https://example.com/verifier"
)

func TestCreateJwt(t *testing.T) {

	privateIssuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	holderPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// SD-JWT Issuer
	issuer := NewSdJwtIssuer(issuerName, privateIssuerKey)
	claims := map[string]string{
		"name":    "John Doe",
		"country": "Japan",
	}
	issuerToken, err := issuer.CreateIssuerToken("test", claims, SHA256, &holderPrivateKey.PublicKey)
	require.NoError(t, err)
	fmt.Printf("%s \n", issuerToken)

	// SD-JWT Holder
	holder := NewDfJwtHolder(holderPrivateKey)
	ok, err := holder.VerifyIssuerToken(issuerToken)
	require.NoError(t, err)
	require.Equal(t, ok, true)

	releaseClaimKeys := []string{"name"}
	holderToken, err := holder.CreateHolderToken(issuerToken, releaseClaimKeys, nonce, audience)
	require.NoError(t, err)

	// SD-JWT Verifier
	verifier := SdJwtVerifier{}
	ok, err = verifier.VerifyHolderToken(holderToken)
	require.NoError(t, err)
	require.Equal(t, ok, true)
}
