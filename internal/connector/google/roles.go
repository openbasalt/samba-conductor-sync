package google

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// AdminRoleGroups implements connector.RoleReader: the IDs of every
// principal that holds an administrator role assignment in the tenant
// (groups and users; a caller looks its group IDs up in it). The read uses
// its own token with the read-only role management scope; it is requested
// only when a group adoption is approved, and an error (the scope not
// granted, the role not allowed to read roles) makes the caller refuse
// every group adoption.
func (g *Connector) AdminRoleGroups(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	token := ""
	for {
		q := url.Values{"maxResults": {"200"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var page struct {
			Items []struct {
				AssignedTo   string `json:"assignedTo"`
				AssigneeType string `json:"assigneeType"`
			} `json:"items"`
			NextPageToken string `json:"nextPageToken"`
		}
		path := apiPrefix + "/customer/" + url.PathEscape(g.cfg.Customer) + "/roleassignments"
		if _, err := g.roles.do(ctx, http.MethodGet, path, q, nil, &page); err != nil {
			return nil, fmt.Errorf("google: list role assignments: %w", err)
		}
		for _, it := range page.Items {
			if it.AssignedTo != "" {
				out[it.AssignedTo] = true
			}
		}
		if page.NextPageToken == "" {
			return out, nil
		}
		token = page.NextPageToken
	}
}

// Ping proves the credential: a token with the connector's scopes and a
// read of one account of the customer. It returns the address read.
func (g *Connector) Ping(ctx context.Context) (string, error) {
	q := url.Values{"customer": {g.cfg.Customer}, "maxResults": {"1"}, "projection": {"basic"}}
	var page struct {
		Users []*apiUser `json:"users"`
	}
	if _, err := g.c.do(ctx, http.MethodGet, apiPrefix+"/users", q, nil, &page); err != nil {
		return "", fmt.Errorf("google: list users: %w", err)
	}
	if len(page.Users) == 0 {
		return "", nil
	}
	return page.Users[0].PrimaryEmail, nil
}
