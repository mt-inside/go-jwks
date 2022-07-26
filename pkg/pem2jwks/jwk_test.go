package pem2jwks

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
