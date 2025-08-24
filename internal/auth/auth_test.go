package auth

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetAPIKey(t *testing.T) {

	testCases := map[string]struct {
		input  http.Header
		expVal string
		expErr string
	}{
		"empty auth header": {
			input:  createAuthHeader(""),
			expErr: "no authorization header included",
		},
		"malformed auth header (not enough parts)": {
			input:  createAuthHeader("awesometestkey"),
			expErr: "malformed authorization header",
		},
		"malformed auth header (absence of ApiKey)": {
			input:  createAuthHeader("Key awesometestkey"),
			expErr: "malformed authorization header",
		},
		"valid auth header": {
			input:  createAuthHeader("ApiKey awesometestkey"),
			expVal: "awesometestkey",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			gotValue, gotErr := GetAPIKey(tc.input)
			diff := cmp.Diff(gotValue, tc.expVal)
			if diff != "" {
				t.Fatal(diff)
			}

			if gotErr == nil {
				if tc.expErr != "" {
					t.Fatalf("expected error: %v, got: <nil>", tc.expErr)
				}
				return
			}

			diff = cmp.Diff(gotErr.Error(), tc.expErr)
			if diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func createAuthHeader(authValue string) http.Header {
	h := http.Header{}
	h.Add("Authorization", authValue)

	return h
}
