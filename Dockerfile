FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
COPY .bin/linux-${TARGETARCH}/revaulter /bin
HEALTHCHECK CMD ["/bin/revaulter", "healthcheck"]
CMD ["/bin/revaulter"]
ENTRYPOINT ["/bin/revaulter"]
