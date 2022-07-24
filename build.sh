#!/bin/bash -ex

export HTTP_PROXY=http://${PROXY_SERVER}
export HTTPS_PROXY=http://${PROXY_SERVER}

export PROJ_NAME="tacrust"
export VERSION=$(git rev-list --count HEAD)
export ITERATION=$(date -u +'%Y%m%d%H%M%S')
export FULL_VERSION="${VERSION}-${ITERATION}"

cd "$(dirname "${BASH_SOURCE[0]}")"
make build-release

mkdir -p rpmbuild/usr/bin
cp target/release/tacrustd rpmbuild/usr/bin/tacrustd

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

