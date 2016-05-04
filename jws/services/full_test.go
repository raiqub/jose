package services

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/raiqub/jose/jwa"
	"github.com/raiqub/jose/jwk"
	"github.com/raiqub/jose/jwk/services"
	"github.com/raiqub/jose/jws/data"
	"github.com/raiqub/jose/jwt"
	"gopkg.in/raiqub/web.v0"

	// Imports to initialize ECDSA, RSA-PKCS#1 and RSA-PSS algorithms
	_ "github.com/raiqub/jose/jwa/ecdsa"
	_ "github.com/raiqub/jose/jwa/pkcs1"
	_ "github.com/raiqub/jose/jwa/pss"
)

const (
	audience   = "testing"
	issuer     = "auth.example.com"
	duration   = time.Second * 10
	keyColName = "keys"
	keySize    = 2048
)

func testCreateAndValidate(alg string, t *testing.T) {
	key, err := jwk.GenerateKey(alg, keySize, 1)
	if err != nil {
		t.Fatalf("Error generating new key: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			jwkset := jwk.Set{Keys: []jwk.Key{*key}}
			web.JSONWrite(w, http.StatusOK, jwkset)
		}))
	defer ts.Close()

	dtAdapter := data.NewSignerMemory()
	dtAdapter.Add(key.ID, key)
	signer, err := NewSigner(Config{
		Issuer:    issuer,
		SetURL:    ts.URL,
		SignKeyID: key.ID,
		Duration:  duration,
	}, dtAdapter)
	if err != nil {
		t.Fatalf("Error creating signer: %v", err)
	}

	token, err := signer.Create(createJWTPayload())
	if err != nil {
		t.Errorf("Error creating token: %v", err)
	}

	if len(strings.TrimSpace(token)) == 0 {
		t.Error("Empty token")
	}

	cliJWKSet := services.NewSetClient(ts.URL)
	verifier, err := NewVerifier(cliJWKSet, issuer)
	if err != nil {
		t.Fatalf("Error creating verifier: %v", err)
	}
	if len(verifier.keys) == 0 {
		t.Fatal("No keys loaded from URL")
	}

	vToken, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("The token cannot be validated: %v", err)
	}
	if vToken == nil {
		t.Error("Invalid token")
	}

	//t.Logf("%s token: %s", alg, token)
}

func TestCreateAndValidateES256(t *testing.T) {
	testCreateAndValidate(jwa.ES256, t)
}

func TestCreateAndValidateES384(t *testing.T) {
	testCreateAndValidate(jwa.ES384, t)
}

func TestCreateAndValidateES512(t *testing.T) {
	testCreateAndValidate(jwa.ES512, t)
}

func TestCreateAndValidateRS256(t *testing.T) {
	testCreateAndValidate(jwa.RS256, t)
}

func TestCreateAndValidateRS384(t *testing.T) {
	testCreateAndValidate(jwa.RS384, t)
}

func TestCreateAndValidateRS512(t *testing.T) {
	testCreateAndValidate(jwa.RS512, t)
}

func TestCreateAndValidatePS256(t *testing.T) {
	testCreateAndValidate(jwa.PS256, t)
}

func TestCreateAndValidatePS384(t *testing.T) {
	testCreateAndValidate(jwa.PS384, t)
}

func TestCreateAndValidatePS512(t *testing.T) {
	testCreateAndValidate(jwa.PS512, t)
}

func createJWTPayload() jwt.Claims {
	return &jwt.CommonClaims{
		Audience: audience,
		Subject:  "gG26se5wyWDOEjaNHwlXm2i9G3mnYGbG62BBq3ZE",
		Scopes:   []string{"owner", "vehicle", "freight"},
		User: &jwt.UserClaims{
			Name:    "John Doe",
			Email:   "john.doe@example.com",
			Country: "USA",
		},
	}
}

func benchmarkTokenCreation(alg string, b *testing.B) {
	key, err := jwk.GenerateKey(alg, keySize, 1)
	if err != nil {
		b.Fatalf("Error generating new key: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			jwkset := jwk.Set{Keys: []jwk.Key{*key}}
			web.JSONWrite(w, http.StatusOK, jwkset)
		}))
	defer ts.Close()

	dtAdapter := data.NewSignerMemory()
	dtAdapter.Add(key.ID, key)
	signer, err := NewSigner(Config{
		Issuer:    issuer,
		SetURL:    ts.URL,
		SignKeyID: key.ID,
		Duration:  duration,
	}, dtAdapter)
	if err != nil {
		b.Fatalf("Error creating signer: %v", err)
	}

	token, err := signer.Create(createJWTPayload())
	if err != nil {
		b.Errorf("Error creating token: %v", err)
	}

	if len(strings.TrimSpace(token)) == 0 {
		b.Error("Empty token")
	}

	cliJWKSet := services.NewSetClient(ts.URL)
	verifier, err := NewVerifier(cliJWKSet, issuer)
	if err != nil {
		b.Fatalf("Error creating verifier: %v", err)
	}
	if len(verifier.keys) == 0 {
		b.Fatal("No keys loaded from URL")
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := verifier.Verify(token)
		if err != nil {
			b.Fatalf("Error validating token: %v", err)
		}
	}

	b.StopTimer()
}

func BenchmarkTokenCreationES256(b *testing.B) {
	benchmarkTokenCreation(jwa.ES256, b)
}

func BenchmarkTokenCreationES384(b *testing.B) {
	benchmarkTokenCreation(jwa.ES384, b)
}

func BenchmarkTokenCreationES512(b *testing.B) {
	benchmarkTokenCreation(jwa.ES512, b)
}

func BenchmarkTokenCreationRS256(b *testing.B) {
	benchmarkTokenCreation(jwa.RS256, b)
}

func BenchmarkTokenCreationRS384(b *testing.B) {
	benchmarkTokenCreation(jwa.RS384, b)
}

func BenchmarkTokenCreationRS512(b *testing.B) {
	benchmarkTokenCreation(jwa.RS512, b)
}

func BenchmarkTokenCreationPS256(b *testing.B) {
	benchmarkTokenCreation(jwa.PS256, b)
}

func BenchmarkTokenCreationPS384(b *testing.B) {
	benchmarkTokenCreation(jwa.PS384, b)
}

func BenchmarkTokenCreationPS512(b *testing.B) {
	benchmarkTokenCreation(jwa.PS512, b)
}

func benchmarkTokenValidation(alg string, b *testing.B) {
	key, err := jwk.GenerateKey(alg, keySize, 1)
	if err != nil {
		b.Fatalf("Error generating new key: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			jwkset := jwk.Set{Keys: []jwk.Key{*key}}
			web.JSONWrite(w, http.StatusOK, jwkset)
		}))
	defer ts.Close()

	dtAdapter := data.NewSignerMemory()
	dtAdapter.Add(key.ID, key)
	signer, err := NewSigner(Config{
		Issuer:    issuer,
		SetURL:    ts.URL,
		SignKeyID: key.ID,
		Duration:  duration,
	}, dtAdapter)
	if err != nil {
		b.Fatalf("Error creating signer: %v", err)
	}

	payload := createJWTPayload()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := signer.Create(payload)
		if err != nil {
			b.Fatalf("Error creating token: %v", err)
		}
	}

	b.StopTimer()
}

func BenchmarkTokenValidationES256(b *testing.B) {
	benchmarkTokenValidation(jwa.ES256, b)
}

func BenchmarkTokenValidationES384(b *testing.B) {
	benchmarkTokenValidation(jwa.ES384, b)
}

func BenchmarkTokenValidationES512(b *testing.B) {
	benchmarkTokenValidation(jwa.ES512, b)
}

func BenchmarkTokenValidationRS256(b *testing.B) {
	benchmarkTokenValidation(jwa.RS256, b)
}

func BenchmarkTokenValidationRS384(b *testing.B) {
	benchmarkTokenValidation(jwa.RS384, b)
}

func BenchmarkTokenValidationRS512(b *testing.B) {
	benchmarkTokenValidation(jwa.RS512, b)
}

func BenchmarkTokenValidationPS256(b *testing.B) {
	benchmarkTokenValidation(jwa.PS256, b)
}

func BenchmarkTokenValidationPS384(b *testing.B) {
	benchmarkTokenValidation(jwa.PS384, b)
}

func BenchmarkTokenValidationPS512(b *testing.B) {
	benchmarkTokenValidation(jwa.PS512, b)
}
