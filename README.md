# hackeroni-ql
A Golang GraphQL client library for HackerOne

For the most part, this library is generated automatically based on a introspection query run against the H1 API. There is some minor scaffolding for some object types and client libraries. It can be updated at any time with new structs as follows:
```shell
get-graphql-schema https://hackerone.com/graphql --json | jq -rf graphql.jq > h1/generated.go
```