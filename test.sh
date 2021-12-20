#!/bin/bash -ex

export HTTP_PROXY=http://${PROXY_SERVER}
export HTTPS_PROXY=http://${PROXY_SERVER}
export TOKEN="66632e33-d018-4a35-afce-3cafcac256cc"

cd "$(dirname "${BASH_SOURCE[0]}")"
cargo make strata
grcov ./target/debug -t coveralls -s . --token $TOKEN --ignore 'vendor/*' --ignore '/rustc/*' > coveralls.json

if [ "$STRATA" == "yes" ]; then
	bash <(curl -s https://codecov.moe.prd-sam.prd.slb.sfdc.net/bash) -t $TOKEN -f coveralls.json -Z
fi

