# Builds the clpaste Docker image (static Alpine binary; see Dockerfile).
#
#   make image            # builds clpaste:<version> and clpaste:latest
#   make image IMAGE=foo  # different image name
#   make run              # runs the image on http://localhost:8080 with a local ./data volume
#   make push REGISTRY=us-east4-docker.pkg.dev/proj/repo

IMAGE    ?= clpaste
VERSION  ?= $(shell sed -n 's/^version: *//p' shard.yml)
GIT_SHA  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
REGISTRY ?=
DOCKER   ?= docker

.PHONY: all image run push clean

all: image

image:
	$(DOCKER) build \
	  --label org.opencontainers.image.version=$(VERSION) \
	  --label org.opencontainers.image.revision=$(GIT_SHA) \
	  --build-arg GIT_SHA=$(GIT_SHA) \
	  -f docker/Dockerfile \
	  -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

run: image
	mkdir -p data
	$(DOCKER) run --rm -it -p 8080:8080 -v $(CURDIR)/data:/data --env-file .env $(IMAGE):$(VERSION)

push: image
	@test -n "$(REGISTRY)" || { echo "REGISTRY is required, e.g. make push REGISTRY=host/project/repo"; exit 1; }
	$(DOCKER) tag $(IMAGE):$(VERSION) $(REGISTRY)/$(IMAGE):$(VERSION)
	$(DOCKER) tag $(IMAGE):$(VERSION) $(REGISTRY)/$(IMAGE):latest
	$(DOCKER) push $(REGISTRY)/$(IMAGE):$(VERSION)
	$(DOCKER) push $(REGISTRY)/$(IMAGE):latest

clean:
	-$(DOCKER) rmi $(IMAGE):$(VERSION) $(IMAGE):latest
