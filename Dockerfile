FROM docker.repo.local.sfdc.net/sfci/kuleana/rust-builder/kuleana-rust-builder:53 AS builder

ENV BUILD_NUMBER=$BUILD_NUMBER

COPY --chown=997 . src
RUN src/build.sh

FROM docker.repo.local.sfdc.net/sfci/docker-images/sfdc_centos7:168

COPY --from=builder /home/rust_builder/src/rpm-generated  /tmp/rpm-generated
RUN yum -y localinstall $(find /tmp/rpm-generated -name "*.rpm" | head -n1) && rm /tmp/rpm-generated/*

ENTRYPOINT ["/usr/bin/tacrustd"]
