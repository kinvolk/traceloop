FROM ubuntu
RUN apt-get update && apt-get install -y \
  curl

# Add all traceloop binaries
ADD traceloop-* /bin/
# Then delete the one we do not need.
RUN mv /bin/traceloop-linux-$(dpkg --print-architecture) /bin/traceloop && rm /bin/traceloop-*
CMD ["/bin/traceloop", "k8s"]
