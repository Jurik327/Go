all:
	go build -o bin/nanscraper

all-linux:
	CGO_ENABLED=1 GOARCH=amd64 GOOS=linux go build -o bin/nanscraper-linux

docker-all-linux:
	docker run -it --mount type=bind,source=${PWD},target=/build -w /build golang:1.16 make all-linux

docker-build:
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -o bin/nanscraper

docker-up:
	docker-compose -f contrib/docker-compose.yml up --build -d

docker-stop:
	docker-compose -f contrib/docker-compose.yml stop

docker-down:
	docker-compose -f contrib/docker-compose.yml down

docker-run: docker-stop docker-up

docker-clean:
	docker-compose -f contrib/docker-compose.yml down -v --rmi all --remove-orphans
