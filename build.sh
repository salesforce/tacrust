#!/bin/bash -ex

PROJ_NAME="tacrust"
VERSION=0.1
ITERATION=$(date -u +'%Y%m%d%H%M%S')

cd "$(dirname "${BASH_SOURCE[0]}")"
cargo make strata
cargo make build-release

mkdir -p rpmbuild/usr/share/tacrust
touch rpmbuild/usr/share/tacrust/todo

mkdir rpm-generated || true
cd rpmbuild && fpm -s dir -t rpm \
	-n "${PROJ_NAME}" \
	-m "kuleana@salesforce.com" \
	--rpm-os linux \
	--iteration "${ITERATION}.el7" \
	--version ${VERSION} \
	--epoch 1 \
	--verbose \
	. && \
	mv *.rpm ../rpm-generated/

