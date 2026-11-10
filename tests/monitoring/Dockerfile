FROM prom/prometheus:v3.16.0@sha256:e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06 AS rules
COPY examples/monitoring /etc/prometheus
COPY examples/monitoring /work/examples/monitoring
COPY tests/monitoring /work/tests/monitoring
WORKDIR /work/tests/monitoring
ENTRYPOINT ["/bin/promtool"]
FROM prom/blackbox-exporter:v0.29.1@sha256:ea1c7aa3ef3f307cd03e85f34abb604478ccb90b567fc690da0cd9776da76b13 AS blackbox
COPY examples/monitoring/blackbox.yml /etc/blackbox_exporter/config.yml
