DEBUG=1
UID=$(shell id -u)
PWD=$(shell pwd)

DOCKER_FILE?=Dockerfile
DOCKER_IMAGE?=kinvolk/straceback-builder

# If you can use docker without being root, you can do "make SUDO="
SUDO=$(shell docker info >/dev/null 2>&1 || echo "sudo -E")

all: build-docker-image build-bpf-object install-generated-go bin-straceback

build-docker-image:
	$(SUDO) docker build -t $(DOCKER_IMAGE) -f $(DOCKER_FILE) .

build-bpf-object:
	$(SUDO) docker run --rm -e DEBUG=$(DEBUG) \
		-e CIRCLE_BUILD_URL=$(CIRCLE_BUILD_URL) \
		-v $(PWD):/src:ro \
		-v $(PWD)/bpf:/dist/ \
		--workdir=/src \
		$(DOCKER_IMAGE) \
		make -f bpf.mk build
	sudo chown -R $(UID):$(UID) bpf

install-generated-go:
	cp bpf/straceback-assets-bpf.go pkg/straceback/straceback-assets-bpf.go

delete-docker-image:
	$(SUDO) docker rmi -f $(DOCKER_IMAGE)

bin-straceback:
	go build -o straceback straceback.go

lint:
	./tools/lint -ignorespelling "agre " -ignorespelling "AGRE " .
	./tools/shell-lint .
