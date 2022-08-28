# Selective Disclosure JWT written in Go
Implementation of selective disclosure JWT.

Do not use in production!

verify process is not complied with SD-JWT [draft](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-00.html).
Only check the claim sd_digests is present in the SD-JWT.

## How to use
There are three types of actors, issuer, holder and verifier.

| Type | Description |
|----- | ----------- |
| SdJwtIssuer   | Issuer that creates a issuer token which contains SD-JWT and SVC |
| SdJwtHolder   | Holder verifies SD-JWT and SVC. Holder creates a holder token, which contains SD-JWT and SD-JWT-R from SD-JWT and SVC. | 
| SdJwtVerifier | Verifier verifies SD-JWT and SD-JWT-R |

### 1. Create Issuer token 
When you want to create issuer token which contains SD-JWT and SVC, generate issure instance and call `CreateIssuerToken()` with nonce, claims which you want to contained, a type of hash algorithm, and holder's public key.

```
	issuer := NewSdJwtIssuer(issuerName, privateIssuerKey)
	claims := map[string]string{
		"name":    "John Doe",
		"country": "Japan",
	}
	issuerToken, err := issuer.CreateIssuerToken(nonce, claims, SHA256, &holderPrivateKey.PublicKey)
```

### 2. Verify issuer token and create holder token
When a holder receives issuer token, the holder verifies the issuer token. And then, holder creates holder token which contains SD-JWT and SD-JWT-R. The process can be done as below. In the below process, holder share its `name` claim to verifier.
```
	holder := NewDfJwtHolder(holderPrivateKey)
	ok, err := holder.VerifyIssuerToken(issuerToken)

	releaseClaimKeys := []string{"name"}
	holderToken, err := holder.CreateHolderToken(issuerToken, releaseClaimKeys, nonce, audience)
```

### 3. Verify Holder token
Finally, verifier verifies holder token as below.
```
	verifier := SdJwtVerifier{}
	ok, err = verifier.VerifyHolderToken(holderToken)
```