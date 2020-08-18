TAG := `git describe --tags --always`
VERSION :=

## Adds a '-dirty' suffix to version string if there are uncommitted changes
changes := $(shell git status --porcelain)
ifeq ($(changes),)
	VERSION := $(TAG)
else
	VERSION := $(TAG)-dirty
endif

VERSIONLDFLAGS := "-X main.version=$(VERSION)"

DEBUG=1
SET_USER=$(shell (docker --version | grep -q podman) || echo "--user $(shell id -u)")
PWD=$(shell pwd)

BUILDER_DOCKER_FILE?=traceloop-builder.Dockerfile
BUILDER_DOCKER_IMAGE?=kinvolk/traceloop-builder

DOCKER_FILE?=traceloop.Dockerfile
IMAGE_TAG=$(shell ./tools/image-tag)
IMAGE_BRANCH_TAG=$(shell ./tools/image-tag branch)
DOCKER_IMAGE?=kinvolk/traceloop:$(IMAGE_TAG)
DOCKER_BRANCH_IMAGE?=kinvolk/traceloop:$(IMAGE_BRANCH_TAG)

# If you can use docker without being root, you can do "make SUDO="
SUDO=$(shell docker info >/dev/null 2>&1 || echo "sudo -E")

.PHONY: all
all: build-docker-image build-bpf-object install-generated-go bin-traceloop test docker/image

build-docker-image:
	$(SUDO) docker build -t $(BUILDER_DOCKER_IMAGE) -f $(BUILDER_DOCKER_FILE) .

# CircleCI with Remote Docker has the following limitation:
# https://circleci.com/docs/2.0/building-docker-images/#mounting-folders
# > It is not possible to mount a folder from your job space into a container
# > in Remote Docker (and vice versa). You may use the docker cp command to
# > transfer files between these two environments.
ifeq ($(CIRCLECI),true)
  DOCKER_VOLUMES=--name bpfbuild --volumes-from sources
else
  DOCKER_VOLUMES=--rm -v $(PWD):/src:ro -v $(PWD)/bpf:/dist/
endif

build-bpf-object:
ifeq ($(CIRCLECI),true)
	docker create -v /src -v /dist --name sources alpine:3.4 /bin/true
	docker cp . sources:/src
endif
	$(SUDO) docker run $(SET_USER) -e DEBUG=$(DEBUG) \
		-e CIRCLE_BUILD_URL=$(CIRCLE_BUILD_URL) \
		$(DOCKER_VOLUMES) \
		--workdir=/src \
		$(BUILDER_DOCKER_IMAGE) \
		make -f bpf.mk build
ifeq ($(CIRCLECI),true)
	docker cp bpfbuild:/dist/straceback-assets-bpf.go bpf/straceback-assets-bpf.go
	docker container rm bpfbuild
	docker container rm sources
endif

install-generated-go:
	cp bpf/straceback-assets-bpf.go pkg/straceback/straceback-assets-bpf.go

delete-docker-image:
	$(SUDO) docker rmi -f $(BUILDER_DOCKER_IMAGE)

tools/golangci-lint: tools/go.mod tools/go.sum
	cd tools && \
		go build -o golangci-lint \
			github.com/golangci/golangci-lint/cmd/golangci-lint

bin-traceloop:
	@echo "Building version $(VERSION)"
	GO111MODULE=on go build \
		-ldflags $(VERSIONLDFLAGS) \
		-o traceloop traceloop.go

.PHONY: test
test:
	go test ./pkg/...

docker/image:
	$(SUDO) docker build -t $(DOCKER_IMAGE) -f $(DOCKER_FILE) .
	$(SUDO) docker tag $(DOCKER_IMAGE) $(DOCKER_BRANCH_IMAGE)

docker/test:
	$(SUDO) docker run -ti --rm --privileged \
		-v /run:/run \
		-v /sys/kernel/debug:/sys/kernel/debug \
		-v /sys/fs/cgroup:/sys/fs/cgroup \
		$(DOCKER_IMAGE)

docker/push:
	$(SUDO) docker push $(DOCKER_IMAGE)
	$(SUDO) docker push $(DOCKER_BRANCH_IMAGE)

lint:
	./tools/lint -ignorespelling "agre " -ignorespelling "AGRE " .
	./tools/shell-lint .
