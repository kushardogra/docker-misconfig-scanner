# Intentionally misconfigured — for testing only
FROM ubuntu:latest

ENV DB_PASSWORD=supersecret123
ENV API_TOKEN=myapitoken
ENV DEBUG=true

ADD https://example.com/setup.sh /setup.sh
RUN curl https://example.com/install.sh | bash

COPY . .
COPY id_rsa /root/.ssh/id_rsa

USER root

EXPOSE 8080
CMD ["bash"]
