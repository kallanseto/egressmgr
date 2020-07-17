FROM golang:alpine AS build

WORKDIR /src/
COPY main.go /src/

# Download all the dependencies
RUN go get -d -v ./...

RUN CGO_ENABLED=0 go build -o /bin/egressmgr

FROM scratch
COPY --from=build /bin/egressmgr /bin/egressmgr

ENTRYPOINT ["/bin/egressmgr"]
