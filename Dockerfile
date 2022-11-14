FROM dva-registry.internal.salesforce.com/sfci/kuleana/rust-builder/kuleana-rust-builder:35 as builder

ENV BUILD_NUMBER=$BUILD_NUMBER

USER root
ADD . /tmp/src
RUN /tmp/src/build.sh

FROM dva-registry.internal.salesforce.com/sfci/docker-images/sfdc_centos7:113

COPY --from=builder /tmp/src/rpm-generated  /tmp/rpm-generated
RUN yum -y localinstall $(find /tmp/rpm-generated -name "*.rpm" | head -n1)

ENTRYPOINT ["/bin/bash"]
