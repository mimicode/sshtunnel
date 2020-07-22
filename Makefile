BUILD_ENV := CGO_ENABLED=0


LDFLAGS=-ldflags "-v -s -w"

TARGET_EXEC:=sshtunnel

.PHONY: all clean setup bl bo bw

all: clean setup bl bo bw

clean:
	rm -rf build

setup:
	mkdir -p build/linux
	mkdir -p build/osx
	mkdir -p build/windows

bl: setup
	${BUILD_ENV} GOARCH=amd64 GOOS=linux go build ${LDFLAGS} -a -v -o build/linux/${TARGET_EXEC}

bo: setup
	${BUILD_ENV} GOARCH=amd64 GOOS=darwin go build ${LDFLAGS} -a -v -o build/osx/${TARGET_EXEC}

bw: setup
	${BUILD_ENV} GOARCH=amd64 GOOS=windows go build ${LDFLAGS} -a -v -o build/windows/${TARGET_EXEC}.exe
