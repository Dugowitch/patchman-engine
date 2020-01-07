#!/bin/bash

source "$(dirname $(realpath "$0"))/env.sh"

curl -v -H "x-rh-identity: $IDENTITY" -XGET http://localhost:8080/api/patch/v1/advisories/$1/systems | python -m json.tool
