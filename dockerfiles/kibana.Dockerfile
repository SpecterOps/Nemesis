 # This file is not in use right now. Need to modify it to initialize data views, dashboards, etc.
FROM docker.elastic.co/kibana/kibana:8.3.3

WORKDIR /usr/share/kibana
ENTRYPOINT ["/bin/tini", "--"]
CMD ["/usr/local/bin/kibana-docker"]
