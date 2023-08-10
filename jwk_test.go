package jwks

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetermineLenE(t *testing.T) {
	cases := []struct {
		e        int
		expected uint
	}{
		{3, 1},
		{5, 1},
		{17, 1},
		{257, 3},
		{65537, 3},
		{1000000, strconv.IntSize / 8},
	}

	for _, cse := range cases {
		got := determineLenE(cse.e)
		require.Equal(t, cse.expected, got, "Field len calculation for E==%d", cse.e)
	}
}

func TestPublicKeyTypes(t *testing.T) {
	var err error

	_, err = PEM2JWK([]byte(rsaPubPEM))
	require.NoError(t, err)

	_, err = PEM2JWK([]byte(ecdsaPubPEM))
	require.NoError(t, err)

	_, err = PEM2JWK([]byte(ed25519PubPEM))
	require.ErrorContains(t, err, "does not support Ed25519")

	_, err = PEM2JWK([]byte(x25519PubPEM))
	require.ErrorContains(t, err, "does not support x25519")

	_, err = PEM2JWK([]byte(ed448PubPEM))
	require.ErrorContains(t, err, "DER block does not encode a recognised cryptographic object")

	_, err = PEM2JWK([]byte(x448PubPEM))
	require.ErrorContains(t, err, "DER block does not encode a recognised cryptographic object")
}

func TestRsaPublicKeyUnmarshal(t *testing.T) {
	// have the key as pem-encoded, parse it in, compare to text source
}
