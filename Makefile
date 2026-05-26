.PHONY: build test vet clean

build:
	go build -trimpath -o vanityssh-go .

test:
	go test -race ./...

vet:
	go vet ./...

clean:
	rm -f vanityssh-go
