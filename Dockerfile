FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
COPY .bin/linux-${TARGETARCH}/revaulter /bin
HEALTHCHECK CMD ["/bin/revaulter", "healthcheck"]
CMD ["/bin/revaulter"]
ENTRYPOINT ["/bin/revaulter"]
