all: run

run:
	go run cmd/atscanner.go -verbose

clean-db:
	dropdb -U atscanner atscanner
	createdb atscanner -O atscanner