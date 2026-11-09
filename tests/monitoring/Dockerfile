FROM prom/prometheus:v3.16.0 AS rules
COPY examples/monitoring /etc/prometheus
COPY examples/monitoring /work/examples/monitoring
COPY tests/monitoring /work/tests/monitoring
WORKDIR /work/tests/monitoring
ENTRYPOINT ["/bin/promtool"]
FROM prom/blackbox-exporter:v0.29.1 AS blackbox
COPY examples/monitoring/blackbox.yml /etc/blackbox_exporter/config.yml
