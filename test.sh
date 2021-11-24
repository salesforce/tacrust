#!/bin/bash -ex

export TOKEN="7209b18b-1fb8-46e1-b532-ab894c3f64d5 "

cd "$(dirname "${BASH_SOURCE[0]}")"
cargo make strata
grcov ./target/debug -t coveralls -s . --token $TOKEN > coveralls.json

if [ "$STRATA" == "yes" ]; then
	bash <(curl -s https://codecov.moe.prd-sam.prd.slb.sfdc.net/bash) -t $TOKEN -f coveralls.json -Z
fi

