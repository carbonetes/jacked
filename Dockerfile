FROM golang:alpine as build

WORKDIR /jacked

COPY / /jacked

RUN go build .

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /tmp

COPY --from=build /jacked/jacked /

ENTRYPOINT ["/jacked"]