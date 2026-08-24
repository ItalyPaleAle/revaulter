FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
COPY .bin/linux-${TARGETARCH}/revaulter /bin
HEALTHCHECK CMD ["/bin/revaulter", "healthcheck"]
CMD ["/bin/revaulter"]
ENTRYPOINT ["/bin/revaulter"]
