FROM ubuntu
ADD straceback /bin/
CMD ["/bin/straceback", "serve"]
