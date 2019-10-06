DEBUG=1
UID=$(shell id -u)
PWD=$(shell pwd)

BUILDER_DOCKER_FILE?=traceloop-builder.Dockerfile
BUILDER_DOCKER_IMAGE?=kinvolk/traceloop-builder

DOCKER_FILE?=traceloop.Dockerfile
IMAGE_TAG=$(shell ./tools/image-tag)
DOCKER_IMAGE?=kinvolk/traceloop:$(IMAGE_TAG)

# If you can use docker without being root, you can do "make SUDO="
SUDO=$(shell docker info >/dev/null 2>&1 || echo "sudo -E")

all: build-docker-image build-bpf-object install-generated-go bin-traceloop docker/image

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
	$(SUDO) docker run -e DEBUG=$(DEBUG) \
		-e CIRCLE_BUILD_URL=$(CIRCLE_BUILD_URL) \
		$(DOCKER_VOLUMES) \
		--workdir=/src \
		$(BUILDER_DOCKER_IMAGE) \
		make -f bpf.mk build
ifeq ($(CIRCLECI),true)
	docker cp bpfbuild:/dist/straceback-assets-bpf.go bpf/straceback-assets-bpf.go
	docker container rm bpfbuild
	docker container rm sources
else
	sudo chown -R $(UID):$(UID) bpf
endif

install-generated-go:
	cp bpf/straceback-assets-bpf.go pkg/straceback/straceback-assets-bpf.go

delete-docker-image:
	$(SUDO) docker rmi -f $(BUILDER_DOCKER_IMAGE)

bin-traceloop:
	GO111MODULE=on go build -o traceloop traceloop.go

docker/image:
	$(SUDO) docker build -t $(DOCKER_IMAGE) -f $(DOCKER_FILE) .

docker/test:
	$(SUDO) docker run -ti --rm --privileged \
		-v /run:/run \
		-v /sys/kernel/debug:/sys/kernel/debug \
		-v /sys/fs/cgroup:/sys/fs/cgroup \
		$(DOCKER_IMAGE)

docker/push:
	$(SUDO) docker push $(DOCKER_IMAGE)

lint:
	./tools/lint -ignorespelling "agre " -ignorespelling "AGRE " .
	./tools/shell-lint .
