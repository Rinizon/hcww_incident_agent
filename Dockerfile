FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV HCWW_AGENT_HOST=0.0.0.0
ENV HCWW_AGENT_PORT=8787

RUN addgroup --system hcww && \
    adduser --system --ingroup hcww --home /app --no-create-home hcww && \
    mkdir -p /app/data && \
    chown -R hcww:hcww /app

COPY --chown=hcww:hcww . /app

USER hcww

EXPOSE 8787

CMD ["python3", "app.py"]
