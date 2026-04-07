# check=error=true

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMAGE=gcr.io/distroless/static:latest@sha256:28efbe90d0b2f2a3ee465cc5b44f3f2cf5533514cf4d51447a977a5dc8e526d0
ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:c4e61715e51fc21158aac47df827861c10d42cbb@sha256:057fdc06402c92c747be59dd2bc0ddfe04b3c25b1df7c15ed1c5b0804053487f

FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} AS builder

ARG TARGETOS
ARG TARGETARCH
ARG MODIFIERS

WORKDIR /go/src/github.com/cilium/cilium

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    git config --global --add safe.directory /go/src/github.com/cilium/cilium && \
    make -C examples/mesh-redirect-plugin generate && \
    make GOARCH=${TARGETARCH} DESTDIR=/out/${TARGETOS}/${TARGETARCH} $(echo $MODIFIERS | tr -d '"') \
    -C examples/mesh-redirect-plugin install

FROM ${BASE_IMAGE} AS release
ARG TARGETOS
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
WORKDIR /root/app
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/local/bin/mesh-redirect-plugin /usr/local/bin/cilium/mesh-redirect-plugin

ENTRYPOINT ["/usr/local/bin/cilium/mesh-redirect-plugin"]
