# Builds saml2aws from the checkout exactly as it is and runs the unit and
# integration tests. Build context: the repository root.
FROM node:20-bookworm-slim AS node

FROM golang:1.22.5-bookworm
ENV GOTOOLCHAIN=local CGO_ENABLED=1

# The playwright-go version pinned in go.mod (v0.4702.0) downloads driver
# 1.47.2 from the retired playwright.azureedge.net CDN. Assemble the same
# driver from npm instead and point playwright-go at it; browser builds still
# exist on the current CDN.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm
ENV PLAYWRIGHT_DRIVER_PATH=/opt/playwright-driver \
    PLAYWRIGHT_DOWNLOAD_HOST=https://cdn.playwright.dev/dbazure/download/playwright \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
# playwright-go looks for the driver in $PLAYWRIGHT_DRIVER_PATH/ms-playwright-go/<version>.
RUN d=$PLAYWRIGHT_DRIVER_PATH/ms-playwright-go/1.47.2 && mkdir -p $d \
 && cd /tmp && npm pack --silent playwright-core@1.47.2 \
 && tar -xzf playwright-core-1.47.2.tgz -C $d \
 && ln -s /usr/local/bin/node $d/node \
 && $d/node $d/package/cli.js install --with-deps chromium \
 && rm -rf /tmp/* /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /usr/local/bin/saml2aws ./cmd/saml2aws && saml2aws --version
