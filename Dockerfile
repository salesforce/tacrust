FROM dva-registry.internal.salesforce.com/dva/kuleana-rust-builder:33 as builder

USER root
ADD . /tmp/src
RUN /tmp/src/build.sh

FROM dva-registry.internal.salesforce.com/dva/sfdc_centos7:92

COPY --from=builder /tmp/src/rpm-generated  /tmp/rpm-generated
RUN yum -y localinstall $(find /tmp/rpm-generated -name "*.rpm" | head -n1)

ENTRYPOINT ["/bin/bash"]
