FROM ubuntu
RUN apt-get update && apt-get install -y \
  curl

ADD straceback /bin/
CMD ["/bin/straceback", "serve"]
