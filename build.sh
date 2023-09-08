#!/bin/bash -ex

env

export HTTP_PROXY=http://${PROXY_SERVER}
export HTTPS_PROXY=http://${PROXY_SERVER}

export EPOCH="2"
export PROJ_NAME="tacrust"
export VERSION=${BUILD_ID}

if [ "${VERSION}" == "" ]; then
	export VERSION="dev"
fi

export ITERATION="$(date -u +'%Y%m%d%H%M%S')"
export FULL_VERSION="${VERSION}-${ITERATION}"

cd "$(dirname "${BASH_SOURCE[0]}")"
make build-release

mkdir -p rpmbuild/usr/bin
cp target/release/tacrustd rpmbuild/usr/bin/tacrustd

mkdir rpm-generated || true
cd rpmbuild && fpm -s dir -t rpm \
	-n "${PROJ_NAME}" \
	-m "platform-integrity-c4ssh@salesforce.com" \
	--rpm-os linux \
	--iteration "${ITERATION}.el7" \
	--version ${VERSION} \
	--epoch ${EPOCH} \
	--verbose \
	. && \
	mv *.rpm ../rpm-generated/

