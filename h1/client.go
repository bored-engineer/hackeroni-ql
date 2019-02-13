package h1

import (
	"github.com/machinebox/graphql"
)

const defaultEndpoint = "https://hackerone.com/graphql"

// NewClient creates a *graphql.Client pointed at H1
func NewClient(opts ...graphql.ClientOption) *graphql.Client {
	return graphql.NewClient(defaultEndpoint, opts...)
}
