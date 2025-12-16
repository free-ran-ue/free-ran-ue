.PHONY: all bin console console-init ns-up ns-down ns-ran ns-ue dc-ns-up dc-ns-down dc-ns-mran dc-ns-sran dc-ns-ue dci-ns-up dci-ns-down dci-ns-mran dci-ns-sran dci-ns-ue dci-ns-iperf-a dci-ns-iperf-b

.DEFAULT_GOAL := bin

all: bin console-init

# Build the binary
bin:
	go build -o build/free-ran-ue main.go

# Build the console
console:
	cd console/frontend && yarn build
	mkdir -p build/console
	cp -r console/frontend/dist/* build/console/
	rm -rf console/frontend/dist

console-init:
	cd console/frontend && yarn install && yarn build
	mkdir -p build/console
	cp -r console/frontend/dist/* build/console/
	rm -rf console/frontend/dist

# Basic namespace
ns-up:
	./script/namespace-script/free-ran-ue-namespace.sh up

ns-down:
	./script/namespace-script/free-ran-ue-namespace.sh down

ns-ran:
	./script/namespace-script/free-ran-ue-namespace.sh ran-ns

ns-ue:
	./script/namespace-script/free-ran-ue-namespace.sh ue-ns

# DC namespace
dc-ns-up:
	./script/namespace-script/free-ran-ue-dc-namespace.sh up

dc-ns-down:
	./script/namespace-script/free-ran-ue-dc-namespace.sh down

dc-ns-mran:
	./script/namespace-script/free-ran-ue-dc-namespace.sh mran-ns

dc-ns-sran:
	./script/namespace-script/free-ran-ue-dc-namespace.sh sran-ns

dc-ns-ue:
	./script/namespace-script/free-ran-ue-dc-namespace.sh ue-ns

# DC Iperf namespace
dci-ns-up:
	./script/namespace-script/free-ran-ue-dc-iperf-namespace.sh up

dci-ns-down:
	./script/namespace-script/free-ran-ue-dc-iperf-namespace.sh down

dci-ns-mran:
	./script/namespace-script/free-ran-ue-dc-iperf-namespace.sh mran-ns

dci-ns-sran:
	./script/namespace-script/free-ran-ue-dc-iperf-namespace.sh sran-ns

dci-ns-ue:
	./script/namespace-script/free-ran-ue-dc-iperf-namespace.sh ue-ns

dci-ns-iperf-a:
	./script/namespace-script/free-ran-ue-dc-iperf-namespace.sh iperf-a

dci-ns-iperf-b:
	./script/namespace-script/free-ran-ue-dc-iperf-namespace.sh iperf-b
