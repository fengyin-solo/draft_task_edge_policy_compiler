FROM python:3.13.15-slim-bookworm@sha256:00faa2debb87529f9f0764e9491d8ba400a3678976616c3bd7cb193745ac20d1

COPY data/ /data/
COPY app/ /app/
COPY generate_data.py /opt/task/generate_data.py

RUN mkdir -p /output /var/lib/edge-policy /logs/verifier \
    && chmod 0755 /app/compile_firewall_policy.py /logs/verifier \
    && python3 /opt/task/generate_data.py --out /tmp/edge-policy-seed \
    && install -m 0644 /tmp/edge-policy-seed/dispatch-journal.jsonl /var/lib/edge-policy/journal.jsonl \
    && rm -rf /tmp/edge-policy-seed

WORKDIR /app
CMD ["sleep", "infinity"]
