package provider

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// The OIDC verifier parses upstream JWKs through go-jose. Keep the upstream
// denial-of-service fix active rather than raising its global modulus limit.
func TestUpstreamJWKModulusBound(t *testing.T) {
	for _, bits := range []int{2048, 4096, 4104} {
		modulus := make([]byte, bits/8)
		modulus[0] = 0x80
		modulus[len(modulus)-1] = 1
		encoded, err := json.Marshal(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "fixture", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(modulus), "e": "AQAB"}}})
		if err != nil {
			t.Fatal(err)
		}
		var keys jose.JSONWebKeySet
		err = json.Unmarshal(encoded, &keys)
		if (err == nil) != (bits <= 4096) {
			t.Fatalf("unexpected JWK parsing result at %d bits", bits)
		}
	}
}
