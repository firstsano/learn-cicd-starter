package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetAPIKey(t *testing.T) {
	type expected struct {
		value string
		err   error
	}

	testCases := map[string]struct {
		name  string
		input http.Header
		exp   expected
	}{
		"empty auth header": {
			input: createAuthHeader(""),
			exp: expected{
				value: "",
				err:   ErrNoAuthHeaderIncluded,
			},
		},
		"malformed auth header (not enough parts)": {
			input: createAuthHeader("awesometestkey"),
			exp: expected{
				value: "",
				err:   errors.New("malformed authorization header"),
			},
		},
		"malformed auth header (absence of ApiKey)": {
			input: createAuthHeader("Key awesometestkey"),
			exp: expected{
				value: "",
				err:   errors.New("malformed authorization header"),
			},
		},
		"valid auth header": {
			input: createAuthHeader("ApiKey awesometestkey"),
			exp: expected{
				value: "awesometestkey",
				err:   nil,
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			gotValue, gotErr := GetAPIKey(tc.input)
			diff := cmp.Diff(gotValue, tc.exp.value)
			if diff != "" {
				t.Fatalf(diff)
			}

			if gotErr == nil {
				if tc.exp.err == nil {
					return
				}

				t.Fatalf("errors mismatch: got %v want <nil>", gotErr)
			}

			diff = cmp.Diff(gotErr.Error(), tc.exp.err.Error())
			if diff != "" {
				t.Fatalf(diff)
			}
		})
	}
}

func createAuthHeader(authValue string) http.Header {
	h := http.Header{}
	h.Add("Authorization", authValue)

	return h
}
