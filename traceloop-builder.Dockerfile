FROM fedora:26

ENV GOPATH /go
ENV PATH "/usr/local/go/bin:$PATH"

# vim-common is needed for xxd
# vim-minimal needs to be updated first to avoid an RPM conflict on man1/vim.1.gz
RUN dnf update -y vim-minimal && \
	dnf install -y llvm clang kernel-devel make binutils vim-common go-bindata ShellCheck git file

RUN curl -fsSLo shfmt https://github.com/mvdan/sh/releases/download/v1.3.0/shfmt_v1.3.0_linux_amd64 && \
	echo "b1925c2c405458811f0c227266402cf1868b4de529f114722c2e3a5af4ac7bb2  shfmt" | sha256sum -c && \
	chmod +x shfmt && \
	mv shfmt /usr/bin
RUN curl -fsSLo go.tar.gz https://golang.org/dl/go1.16.4.linux-amd64.tar.gz && \
	echo "7154e88f5a8047aad4b80ebace58a059e36e7e2e4eb3b383127a28c711b4ff59  go.tar.gz" | sha256sum -c && \
	mkdir -p /usr/local && \
	tar -C /usr/local -xzf go.tar.gz
RUN go get -u github.com/fatih/hclfmt

RUN mkdir -p /src /go
