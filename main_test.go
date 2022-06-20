package main

import (
	"strconv"
	"testing"
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
		if got != cse.expected {
			t.Errorf("Field len calculation for E==%d: got %d, expected %d.", cse.e, got, cse.expected)
		}
	}
}
