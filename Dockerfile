FROM docker.repo.local.sfdc.net/sfci/kuleana/rust-builder/kuleana-rust-builder:41 as builder

ENV BUILD_NUMBER=$BUILD_NUMBER

RUN useradd -d /home/tacrust -m -s /bin/bash tacrust
USER tacrust
COPY --chown=tacrust . /tmp/src
RUN /tmp/src/build.sh

FROM docker.repo.local.sfdc.net/sfci/docker-images/sfdc_centos7:146
RUN useradd -d /home/tacrust -m -s /bin/bash tacrust
USER tacrust

COPY --chown=tacrust --from=builder /tmp/src/rpm-generated  /tmp/rpm-generated
RUN yum -y localinstall $(find /tmp/rpm-generated -name "*.rpm" | head -n1)

ENTRYPOINT ["/bin/bash"]
