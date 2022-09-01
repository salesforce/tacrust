#!/bin/bash -ex

cd "$(dirname "${BASH_SOURCE[0]}")"

generate_coverage_report () {
	export TOKEN="66632e33-d018-4a35-afce-3cafcac256cc"
	grcov ./target/debug -t coveralls -s . --token $TOKEN --ignore 'vendor/*' --ignore '/rustc/*' > coveralls.json
	bash <(curl -s https://codecov.moe.prd-sam.prd.slb.sfdc.net/bash) -t $TOKEN -f coveralls.json -Z
}

test_functionality () {
	export RUST_LOG=debug
	make
}

test_deadlocks () {
	./target/debug/tacrustd --listen-address=0.0.0.0:4949 &

	sleep 5

	parallel --halt now,fail=1 --timeout 5 --jobs 100 \
		tacacs_client -u faramir -r 172.16.100.12 -H 127.0.0.1 -p 4949 -k tackey -d authorize -c service=junos-{} \
		::: $(seq 1 1000)

	PARALLEL_RETCODE=$?
	kill -9 %1
	return $PARALLEL_RETCODE
}

install_tacacs_client () {
	yum install -y python3-pip
	pip3 install -r pip/requirements.txt --no-index --find-links pip/vendor
}

if [ "$STRATA" == "yes" ]; then
	install_tacacs_client
fi

echo "Testing functionality (unit and integration tests)"
test_functionality

echo "Testing deadlocks"
test_deadlocks

