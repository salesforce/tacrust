#!/bin/bash -ex

env

export HTTP_PROXY=http://${PROXY_SERVER}
export HTTPS_PROXY=http://${PROXY_SERVER}

export EPOCH="2"
export PROJ_NAME="tacrust"
export VERSION_NUMBER="${BUILD_ID}"

ITERATION=$(date +"%Y%m%d%H%M%S")
echo ${ITERATION} > .iteration

if [ -f /etc/os-release ]; then
    # freedesktop.org and systemd
    . /etc/os-release
    DIST=$VERSION_ID
fi

if [ "${VERSION_NUMBER}" == "" ]; then
	export VERSION_NUMBER="dev"
fi

export FULL_VERSION="${VERSION_NUMBER}-${ITERATION}"

cd "$(dirname "${BASH_SOURCE[0]}")"
make build-release

mkdir -p rpmbuild/usr/bin
cp target/release/tacrustd rpmbuild/usr/bin/tacrustd
mkdir rpm-generated || true

if [[ "${DIST}" == 7 ]]; then
    cd rpmbuild && fpm -s dir -t rpm \
	-n "${PROJ_NAME}" \
	-m "platform-integrity-c4ssh@salesforce.com" \
	--rpm-os linux \
	--iteration "${ITERATION}.el7" \
	--version ${VERSION_NUMBER} \
	--epoch ${EPOCH} \
	--verbose \
        . && \
	mv *.rpm ../rpm-generated/
elif [[ "${DIST}" =~ ^9.* ]]; then
    if [ ! -f .iteration ]; then # if building locally (for example), there won't be a .iteration file from the CE7 packaging container
        ITERATION=$(date +"%Y%m%d%H%M%S")
    else 
        ITERATION=$(cat .iteration)
    fi
    echo "ITERATION: ${ITERATION}"
    export ITERATION
    cd rpmbuild && fpm -s dir -t rpm \
        -n "${PROJ_NAME}" \
        -m "platform-integrity-c4ssh@salesforce.com" \
        --rpm-os linux \
        --iteration "${ITERATION}.el9" \
        --version ${VERSION_NUMBER} \
	--epoch ${EPOCH} \
	--verbose \
        . && \
	mv *.rpm ../rpm-generated/
fi
