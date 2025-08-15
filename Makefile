MODULE = github.com/iofinnet/tss-lib/v3
PACKAGES = $(shell go list ./... | grep -v '/vendor/')
UT_TIMEOUT = -timeout 60m
UT_COVER = -covermode=atomic -cover
UT_PACKAGES_LEVEL_0 = $(shell go list ./... | grep -v '/vendor/' | grep 'keygen' )
UT_PACKAGES_LEVEL_1 = $(shell go list ./... | grep -v '/vendor/' | grep -v 'keygen'  )

all: protob test

########################################
### Protocol Buffers

protob:
	@echo "--> Building Protocol Buffers using buf"
	@go tool buf generate

########################################
### Format

fmt:
	@go fmt ./...

lint:
	@golangci-lint run

build: protob
	go fmt ./...

########################################
### Testing

test_unit_level0:
	@echo "--> Running Unit Tests - Level 0"
	@echo "!!! WARNING: This will take a long time :|"
	@echo "!!! WARNING: This will delete fixtures"
	go clean -testcache
	rm -f ./test/_ecdsa_fixtures/*json
	rm -f ./test/_schnorr_fixtures/*json
	go test -failfast ${UT_TIMEOUT} ${UT_COVER} $(UT_PACKAGES_LEVEL_0)


test_unit: test_unit_level0
	@echo "--> Running Unit Tests - Level 1"
	@echo "!!! WARNING: This will take a long time :|"
	go test -failfast ${UT_TIMEOUT} ${UT_COVER} $(UT_PACKAGES_LEVEL_1)

test_unit_race_level0:
	@echo "--> Running Unit Tests (with Race Detection) - Level 0"
	@echo "!!! WARNING: This will take a long time :|"
	@echo "!!! WARNING: This will delete fixtures"
	go clean -testcache
	rm -f ./test/_ecdsa_fixtures/*json
	rm -f ./test/_schnorr_fixtures/*json
	go test -failfast -race ${UT_TIMEOUT} $(UT_PACKAGES_LEVEL_0)

test_unit_race: test_unit_race_level0
	@echo "--> Running Unit Tests (with Race Detection) - Level 1"
	@echo "!!! WARNING: This will take a long time :|"
	go test -failfast -race ${UT_TIMEOUT} ${UT_COVER} $(UT_PACKAGES_LEVEL_1)

test_unit_race_ci: test_unit_race_level0
	@echo "--> Running Unit Tests (with Race Detection) - Level 1"
	@echo "!!! WARNING: This will take a long time :|"
	go test -failfast -race ${UT_TIMEOUT} $(UT_PACKAGES_LEVEL_1)

test:
	make test_unit_race

test_ci:
	make test_unit_race_ci

########################################
### Pre Commit

pre_commit: build test

########################################

# To avoid unintended conflicts with file names, always add to .PHONY
# # unless there is a reason not to.
# # https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: protob build test test_ci test_unit test_unit_race
