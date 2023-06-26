# easyss server
# usage:
#
# docker run -it -d --name easyss --network host nange/docker-easyss:latest -p 9999 -k yourpassword -s yourdomain.com
#
FROM ubuntu:latest

LABEL maintainer=LanceLi

WORKDIR /tmp

RUN apt-get update

RUN apt-get install -y zip wget

ARG VERSION

RUN wget "https://github.com/nange/easyss/releases/download/${VERSION}/easyss-server-linux-amd64.zip"

RUN unzip easyss-server-linux-amd64.zip && rm easyss-server-linux-amd64.zip

RUN mkdir -p /opt/easyss

RUN mv ./easyss-server /opt/easyss

RUN chmod +x /opt/easyss/easyss-server

ENTRYPOINT ["/opt/easyss/easyss-server"]