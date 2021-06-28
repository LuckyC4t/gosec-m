FROM golang:alpine

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
RUN apk add --update --no-cache ca-certificates bash git

RUN mkdir -p /gosec-m
WORKDIR /gosec-m
COPY . /gosec-m
ENV GOPROXY=https://goproxy.io
ENV GO111MODULE on

RUN cd cmd/gosec && go generate && go build -o gosec-m
RUN cp /gosec-m/cmd/gosec/gosec-m /bin/gosec-m

COPY entrypoint.sh /bin/entrypoint.sh
ENTRYPOINT ["/bin/entrypoint.sh"]