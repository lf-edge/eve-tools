proto-container-build:
	docker build -f Dockerfile -t runtimemetrics-builder .

gen-go:
	docker run --rm --env HOME=/src -v $(PWD):/src -w /src -u $$(id -u) runtimemetrics-builder make proto

.PHONY: proto-api-% proto proto-container-build gen-go

# Target run in runtimemetrics-builder 'proto-container-build'
proto: go
	@echo Done building protobuf, you may want to vendor it into your projects, e.g. lf-edge/eve.
	@echo See ./go/README.md for more information.

# Target run in the runtimemetrics-builder 'proto-container-build'
go: PROTOC_OUT_OPTS=paths=source_relative:
go: proto-api-go

# Target run in the runtimemetrics-builder 'proto-container-build'
proto-api-%:
	rm -rf $*/*/; mkdir -p $* # building $@
	protoc -I./proto --$(*)_out=$(PROTOC_OUT_OPTS)./$* proto/*/*.proto

help:
	@echo "runtimemetrics contains proto objects to generate structures for the webserver running inside an"
	@echo "	eve runtime vm which reports nested app instance metrics"
	@echo
	@echo "Commonly used maintenance and development targets:"
	@echo "   proto-container-build      if you have not built this repo before, build the container"
	@echo "   gen-go                     to build and output go objects"