# hackeroni-ql [![GoDoc][doc-img]][doc] 
A Golang GraphQL client library for HackerOne

For the most part, this library is generated automatically based on a introspection query run against the H1 API. There is some minor scaffolding for [DateTime](h1/datetime.go) and [URI](h1/uri.go) object types and a [few helper functions](h1/h1.go). It can be updated at any time with new structs as follows:
```shell
get-graphql-schema https://hackerone.com/graphql --json | jq -rf graphql.jq > h1/generated.go
```
The libary itself has no dependencies beyond the stdlib and must be used in combination with either `net/http` or an existing GraphQL client like [machinebox/graphql](https://github.com/machinebox/graphql).

Example usage of the library is provided below using the [machinebox/graphql](https://github.com/machinebox/graphql) client:
```go
client := graphql.NewClient(h1.GraphQLEndpoint)
req := graphql.NewRequest(`{
  user(username:"bored-engineer") {
    name
  }
}`)

var resp h1.Query
if err := client.Run(context.TODO(), req, &resp); err != nil {
	log.Fatal(err)
}

log.Println(*resp.User.Name) // Luke Young
```
For some real-world usage, checkout [hackeroni-slack-disclosure-bot](https://github.com/bored-engineer/hackeroni-slack-disclosure-bot/)

[doc-img]: https://godoc.org/github.com/bored-engineer/hackeroni-ql/h1?status.svg
[doc]: https://godoc.org/github.com/bored-engineer/hackeroni-ql/h1
