# Development tasks. Tool versions are exact and bumped by hand together
# with .github/workflows/ci.yml.

GO ?= go
GOLANGCI_LINT_VERSION := v2.14.0
GOVULNCHECK_VERSION := v1.8.0
# Kubernetes control plane binaries for the conformance suite
# (kubernetes-sigs/controller-tools envtest releases, sha512 from its
# envtest-releases.yaml).
ENVTEST_K8S_VERSION := 1.36.2
HELM_VERSION := v4.3.0
IMAGE ?= ghcr.io/redundantdns/cert-manager-webhook:dev
TEST_ZONE_NAME ?= example.com.

OS := $(shell $(GO) env GOOS)
ARCH := $(shell $(GO) env GOARCH)
BIN := _bin

ENVTEST_SHA512_linux_amd64 := ea743186c8a799f5cf8faf16969f86189d003cb7d130e0ac4b58789f1e5748dcf30ebe91c837a10d5ac415383da3e10b9e64d65785c938c23e739781cfb76f08
ENVTEST_SHA512_linux_arm64 := 2d72ee985a8e262a3c57dc9f7f0fd891f6a8c7bf7ebaa2db6dc6d8eac8ae28181afe51c1f368b67756cdb40b10de9b205609e1726e5f27f7c6d824dd9c6649ac
ENVTEST_SHA512_darwin_amd64 := b4fe9f973cd1992e3880f8b230ed32c0c243b83371591e3e3315f4404df2cdbef8ee94eeb9bb245b7e5feb987d5c4a76c43e0877654ab73f00d7bbc2b9984514
ENVTEST_SHA512_darwin_arm64 := 9278f9e5af556b2f1f2d139769c1f0d717c7b4426917fdebdba898bcb725a916e4910d6160886194ff9be9589ea7c5c32c2b8ae0754703874b7c8ba8ddfc41ce
HELM_SHA256_linux_amd64 := 86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb
HELM_SHA256_linux_arm64 := 31c5794dd55c66a51e6b7d2e2ac7a114ae8b1de41ff1d9ba51748ac973b06a08
HELM_SHA256_darwin_amd64 := 347a784877e0e20eac865e8d1c36a80f6bb0861d6f29abd34defb6570ef95d92
HELM_SHA256_darwin_arm64 := d3870437e1e95b67f8edbde964156c84a26503f560821d40c542441658934fba

ENVTEST_DIR := $(BIN)/envtest-$(ENVTEST_K8S_VERSION)-$(OS)-$(ARCH)
HELM := $(BIN)/helm-$(HELM_VERSION)-$(OS)-$(ARCH)/helm

.PHONY: all vet test lint vuln check test-conformance helm-lint image clean

all: check

vet:
	$(GO) vet ./...
	$(GO) vet -tags conformance ./...

test:
	$(GO) test -race -count=1 ./...

lint:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --build-tags conformance ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

check: vet test lint vuln helm-lint

# The cert-manager conformance suite (main_test.go) against the go-client
# fake and an in-process DNS server; set RDNS_API_URL and RDNS_TOKEN (and
# optionally RDNS_DNS_SERVER, RDNS_ZONE_ID) to run it against a deployment.
test-conformance: $(ENVTEST_DIR)/kube-apiserver
	TEST_ZONE_NAME=$(TEST_ZONE_NAME) \
	TEST_ASSET_ETCD=$(abspath $(ENVTEST_DIR))/etcd \
	TEST_ASSET_KUBE_APISERVER=$(abspath $(ENVTEST_DIR))/kube-apiserver \
	TEST_ASSET_KUBECTL=$(abspath $(ENVTEST_DIR))/kubectl \
	$(GO) test -tags conformance -count=1 -v -run TestConformance .

$(ENVTEST_DIR)/kube-apiserver:
	@test -n "$(ENVTEST_SHA512_$(OS)_$(ARCH))" || { echo "no pinned envtest checksum for $(OS)/$(ARCH)"; exit 1; }
	mkdir -p $(ENVTEST_DIR)
	curl -fsSL -o $(ENVTEST_DIR).tar.gz \
		https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-v$(ENVTEST_K8S_VERSION)/envtest-v$(ENVTEST_K8S_VERSION)-$(OS)-$(ARCH).tar.gz
	echo "$(ENVTEST_SHA512_$(OS)_$(ARCH))  $(ENVTEST_DIR).tar.gz" | sha512sum -c -
	tar -xzf $(ENVTEST_DIR).tar.gz -C $(ENVTEST_DIR) --strip-components=2
	rm -f $(ENVTEST_DIR).tar.gz

$(HELM):
	@test -n "$(HELM_SHA256_$(OS)_$(ARCH))" || { echo "no pinned helm checksum for $(OS)/$(ARCH)"; exit 1; }
	mkdir -p $(dir $(HELM))
	curl -fsSL -o $(dir $(HELM))helm.tar.gz https://get.helm.sh/helm-$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz
	echo "$(HELM_SHA256_$(OS)_$(ARCH))  $(dir $(HELM))helm.tar.gz" | sha256sum -c -
	tar -xzf $(dir $(HELM))helm.tar.gz -C $(dir $(HELM)) --strip-components=1 $(OS)-$(ARCH)/helm
	rm -f $(dir $(HELM))helm.tar.gz

helm-lint: $(HELM)
	$(HELM) lint --strict deploy/chart
	$(HELM) template rdns-webhook deploy/chart --namespace cert-manager > /dev/null
	$(HELM) template rdns-webhook deploy/chart --namespace cert-manager \
		--set networkPolicy.enabled=false --set podDisruptionBudget.enabled=false \
		--set image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 > /dev/null

# Needs the go-client replace removed from go.mod (see README, "Before
# release"): the build context holds this repository only.
image:
	docker build --build-arg VERSION=dev -t $(IMAGE) .

clean:
	rm -rf $(BIN)
