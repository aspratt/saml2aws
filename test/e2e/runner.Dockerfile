# Builds saml2aws from the checkout exactly as it is and runs the unit and
# integration tests. Build context: the repository root.

# No golang:1.27.3 image is published yet; start from the newest bookworm
# image and let Go fetch the exact toolchain go.mod asks for (checksum-verified).
FROM golang:1.27.1-bookworm
ENV GOTOOLCHAIN=go1.27.3 CGO_ENABLED=1

WORKDIR /src
COPY go.mod go.sum ./
RUN go version && go mod download
# Chromium for the Browser provider tests, from the pinned playwright-go's own
# installer: it fetches its driver (npm) and Node.js (nodejs.org) itself, then
# the browser and Chromium's OS dependencies. No environment overrides.
RUN go run github.com/mxschmitt/playwright-go/cmd/playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/*
COPY . .
RUN go version | grep -q 'go1.27.3 ' \
 && go build -o /usr/local/bin/saml2aws ./cmd/saml2aws && saml2aws --version
