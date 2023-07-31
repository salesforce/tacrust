FROM docker.repo.local.sfdc.net/sfci/kuleana/rust-builder/kuleana-rust-builder:41 as builder

ENV BUILD_NUMBER=$BUILD_NUMBER

USER 0
COPY . /tmp/src
RUN /tmp/src/build.sh

FROM docker.repo.local.sfdc.net/sfci/docker-images/sfdc_centos7:146

COPY --from=builder /tmp/src/rpm-generated  /tmp/rpm-generated
RUN yum -y localinstall $(find /tmp/rpm-generated -name "*.rpm" | head -n1)

ENTRYPOINT ["/bin/bash"]
