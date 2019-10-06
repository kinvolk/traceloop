FROM ubuntu
RUN apt-get update && apt-get install -y \
  curl

ADD traceloop /bin/
CMD ["/bin/traceloop", "k8s"]
