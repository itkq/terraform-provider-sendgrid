// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kenzo0107/sendgrid"
)

// Accounts that cannot use Subusers get 403 from GET /v3/teammates/{name}/subuser_access with this body.
const subuserAccessForbiddenBody = `{"message":"you do not have permission to access this resource"}`

func TestGetTeammateSubuserAccess(t *testing.T) {
	tests := []struct {
		name                 string
		status               int
		body                 string
		managesSubuserAccess bool
		wantErr              bool
		wantSkipped          bool
		wantAccess           int
	}{
		{"ok", http.StatusOK, `{"has_restricted_subuser_access":true,"subuser_access":[{"id":1,"username":"sub","permission_type":"admin"}]}`, false, false, false, 1},
		{"forbidden and not managed", http.StatusForbidden, subuserAccessForbiddenBody, false, false, true, 0},
		{"forbidden and managed", http.StatusForbidden, subuserAccessForbiddenBody, true, true, false, 0},
		// A 403 with an errors array is a plain error without a status code, so it is not skipped.
		{"forbidden with errors body", http.StatusForbidden, `{"errors":[{"field":null,"message":"access forbidden"}]}`, false, true, false, 0},
		{"server error", http.StatusInternalServerError, `{"message":"internal error"}`, false, true, false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/teammates/teammate@example.com/subuser_access" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			t.Cleanup(srv.Close)

			r := &ssoTeammateResource{client: sendgrid.New("dummy", sendgrid.OptionBaseURL(srv.URL))}
			sa, skipped, err := r.getTeammateSubuserAccess(context.Background(), "teammate@example.com", tt.managesSubuserAccess)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %t", err, tt.wantErr)
			}
			if skipped != tt.wantSkipped {
				t.Errorf("skipped = %t, want %t", skipped, tt.wantSkipped)
			}
			if err == nil && len(sa.SubuserAccess) != tt.wantAccess {
				t.Errorf("len(SubuserAccess) = %d, want %d", len(sa.SubuserAccess), tt.wantAccess)
			}
		})
	}
}
