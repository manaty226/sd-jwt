package sdjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type HashType string

const (
	SHA256 HashType = "sha256"
)

func (h HashType) Hashed(data []byte) []byte {
	switch h {
	case SHA256:
		hased := sha256.Sum256(data)
		return hased[:]
	default:
		hased := sha256.Sum256(data)
		return hased[:]
	}
}

type Svc struct {
	SdRelease map[string][2]string `json:"sd_release"`
}

type SdJwt struct {
	HashAlg  string            `json:"sd_hash_alg"`
	SdDigest map[string]string `json:"sd_digests"`
}

// For SD-JWT Issuer
type SdJwtIssuer struct {
	Issuer     string
	PrivateKey *rsa.PrivateKey
}

func NewSdJwtIssuer(issuer string, privateKey *rsa.PrivateKey) *SdJwtIssuer {
	sdJwtIssuer := &SdJwtIssuer{
		Issuer:     issuer,
		PrivateKey: privateKey,
	}
	return sdJwtIssuer
}

func (sd *SdJwtIssuer) CreateIssuerToken(nonce string, claims map[string]string, hashType HashType, holderPubKey *rsa.PublicKey) (string, error) {
	jwtBuilder := jwt.NewBuilder()

	jwtBuilder.Issuer(sd.Issuer).
		IssuedAt(time.Now().Add(30*time.Minute)).
		Expiration(time.Now()).
		Claim("sd_hash_alg", hashType)

	if holderPubKey != nil {
		cnf := struct {
			Kty string `json:"kty"`
			E   string `json:"e"`
			N   string `json:"n"`
		}{
			"RSA",
			base64.URLEncoding.EncodeToString(sd.PrivateKey.PublicKey.N.Bytes()),
			base64.URLEncoding.EncodeToString(big.NewInt(int64(sd.PrivateKey.PublicKey.E)).Bytes()),
		}
		jwtBuilder.Claim("sub_jwk", cnf)
	}

	svcClaims := map[string][2]string{}
	sdDigest := map[string]string{}
	for k, v := range claims {
		hashedValue, salt := createSdClaim(v, hashType)
		svcClaims[k] = [2]string{salt, v}
		sdDigest[k] = hashedValue
	}
	jwtBuilder.Claim("sd_digests", sdDigest)
	svc, err := json.Marshal(Svc{svcClaims})
	if err != nil {
		return "", err
	}
	svcBase64 := base64.RawURLEncoding.EncodeToString(svc)

	sdJwtDoc, err := jwtBuilder.Build()
	if err != nil {
		return "", err
	}

	signedSdJwt, err := jwt.Sign(sdJwtDoc, jwt.WithKey(jwa.RS256, sd.PrivateKey))
	if err != nil {
		return "", err
	}

	return combineTokens(signedSdJwt, []byte(svcBase64)), nil
}

func createSdClaim(value string, hashType HashType) (string, string) {
	salt, err := generateSalt(16)
	if err != nil {
		return "", ""
	}
	sdClaim := base64.RawURLEncoding.EncodeToString(hashType.Hashed([]byte(string(salt) + value)))
	base64Salt := base64.RawURLEncoding.EncodeToString(salt)
	return sdClaim, base64Salt
}

func generateSalt(byteSize uint32) ([]byte, error) {
	salt := make([]byte, byteSize)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func combineTokens(tokens ...[]byte) string {
	combinedToken := string(tokens[0])
	for _, t := range tokens[1:] {
		combinedToken = combinedToken + "." + string(t)
	}
	return combinedToken
}

// For SD-JWT Holder
type SdJwtHolder struct {
	PrivateKey *rsa.PrivateKey
}

func NewDfJwtHolder(privateKey *rsa.PrivateKey) *SdJwtHolder {
	return &SdJwtHolder{
		PrivateKey: privateKey,
	}
}

func (sh SdJwtHolder) CreateHolderToken(issuerToken string, releaseClaimKeys []string, nonce string, aud string) (string, error) {

	// split issuer token to SD-JWT and SVC
	splitIssuerTokens := strings.Split(issuerToken, ".")
	svcByte, err := base64.RawURLEncoding.DecodeString(splitIssuerTokens[3])
	if err != nil {
		return "", err
	}
	var svc Svc
	err = json.Unmarshal(svcByte, &svc)

	sdJwtRelease, err := sh.createSdJwtRelease(svc, releaseClaimKeys, nonce, aud)
	if err != nil {
		return "", err
	}

	sdJwt := strings.Join(splitIssuerTokens[:3], ".")

	return combineTokens([]byte(sdJwt), sdJwtRelease), nil
}

func (sh SdJwtHolder) createSdJwtRelease(svc Svc, releaseClaimKeys []string, nonce string, aud string) ([]byte, error) {
	jwtBuilder := jwt.NewBuilder()
	jwtBuilder.
		Claim("nonce", nonce).
		Claim("aud", aud)

	sdRelease := map[string][2]string{}
	for _, key := range releaseClaimKeys {
		sdRelease[key] = svc.SdRelease[key]
	}
	jwtBuilder.Claim("sd_release", sdRelease)

	sdReleaseJwt, err := jwtBuilder.Build()
	if err != nil {
		return nil, err
	}

	signedSdJwtRelease, err := jwt.Sign(sdReleaseJwt, jwt.WithKey(jwa.RS256, sh.PrivateKey))
	if err != nil {
		return nil, err
	}

	return signedSdJwtRelease, nil
}

func (sh SdJwtHolder) VerifyIssuerToken(issuerToken string) (bool, error) {
	splitIssuerTokens := strings.Split(issuerToken, ".")
	var sdJwt SdJwt
	// extract SD-JWT DOC from issuer token
	sdJwtDoc, err := base64.RawURLEncoding.DecodeString(splitIssuerTokens[1])
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal([]byte(sdJwtDoc), &sdJwt); err != nil {
		return false, err
	}

	// extract SVC from issuer token
	svcByte, err := base64.RawURLEncoding.DecodeString(splitIssuerTokens[3])
	if err != nil {
		return false, err
	}
	var svc Svc
	if err := json.Unmarshal(svcByte, &svc); err != nil {
		return false, err
	}

	// If match all digest of SD-JWT and SVC
	if ok, err := ismatchDigests(sdJwt.SdDigest, svc.SdRelease, HashType(sdJwt.HashAlg)); !ok {
		return false, err
	}

	return true, nil
}

func createHashedValue(salt, value string, hashType HashType) string {
	return base64.RawURLEncoding.EncodeToString(hashType.Hashed([]byte(salt + value)))
}

func ismatchDigests(sdJwtDigests map[string]string, releaseDigests map[string][2]string, hashType HashType) (bool, error) {
	// check all reLease claim's keys exist in SD-JWT sd_digests and match release claim's hashed values.
	for key, values := range releaseDigests {
		digest, ok := sdJwtDigests[key]
		if !ok {
			return false, fmt.Errorf("digests of SD-JWT and SVC are unmatch: %s", key)
		}
		salt, err := base64.RawURLEncoding.DecodeString(values[0])
		if err != nil {
			return false, fmt.Errorf("internal server error")
		}
		hashedValue := createHashedValue(string(salt), values[1], hashType)
		if digest != hashedValue {
			return false, fmt.Errorf("digests of SD-JWT and SVC are unmatch: %s", key)
		}
	}
	return true, nil
}

// SD-JWT Verifier
type SdJwtVerifier struct {
}

type SdJwtRelease struct {
	SdRelease map[string][2]string `json:"sd_release"`
}

func (vf SdJwtVerifier) VerifyHolderToken(holderToken string) (bool, error) {
	splitHolderToken := strings.Split(holderToken, ".")
	if len(splitHolderToken) != 6 {
		return false, fmt.Errorf("holder token has to have 6 period-separeted elements ")
	}
	var sdJwt SdJwt
	// extract SD-JWT DOC from issuer token
	sdJwtDoc, err := base64.RawURLEncoding.DecodeString(splitHolderToken[1])
	if err != nil {
		fmt.Printf("decode SD-JWT: %v \n", err)
		return false, err
	}
	if err := json.Unmarshal([]byte(sdJwtDoc), &sdJwt); err != nil {
		fmt.Printf("%v \n", err)
		return false, err
	}

	// extract SVC from issuer token
	sdJwtReleaseByte, err := base64.RawURLEncoding.DecodeString(splitHolderToken[4])
	if err != nil {
		fmt.Printf("decode SD-JWT-R: %v \n", err)
		return false, err
	}
	var sdr SdJwtRelease
	if err := json.Unmarshal(sdJwtReleaseByte, &sdr); err != nil {
		fmt.Printf("Unmarshal SD-JWT-R: %v \n", err)
		return false, err
	}

	// If match all digest of SD-JWT and SVC
	if ok, err := ismatchDigests(sdJwt.SdDigest, sdr.SdRelease, HashType(sdJwt.HashAlg)); !ok {
		fmt.Printf("%v \n", err)
		return false, err
	}

	return true, nil
}
