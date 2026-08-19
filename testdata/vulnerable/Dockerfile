# Intentionally misconfigured — for testing only
FROM ubuntu:latest

ENV DB_PASSWORD=supersecret123
ENV API_TOKEN=myapitoken

RUN apt-get update && apt-get install -y curl

EXPOSE 8080

CMD ["bash"]
