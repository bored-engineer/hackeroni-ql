#!/bin/bash

get-graphql-schema https://hackerone.com/graphql --json | jq -rf graphql.jq > h1/generated.go