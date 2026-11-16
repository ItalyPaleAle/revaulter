FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
COPY .bin/linux-${TARGETARCH}/revaulter /bin
HEALTHCHECK CMD ["/bin/revaulter", "healthcheck"]
CMD ["/bin/revaulter"]
ENTRYPOINT ["/bin/revaulter"]
