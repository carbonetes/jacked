FROM golang:alpine as build

RUN apk update

WORKDIR /jacked

COPY / /jacked

RUN go build .

CMD [ "/bin/sh" ]

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /tmp

COPY --from=build /jacked/jacked /

ENTRYPOINT ["/jacked"]