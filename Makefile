TARGETS = govfeed govfeed-test
GO = GOPATH=$(shell pwd):$(shell go env GOROOT)/bin go

all: $(TARGETS)

depends:

govfeed:
	$(GO) install govfeed

govfeed-test:
	$(GO) install govfeed-test

clean:
	rm -f bin/govfeed-test
	rm -rf pkg/*
