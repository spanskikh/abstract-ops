FROM sandbox-init-verifier:latest

WORKDIR /app
RUN rm -rf /app/src/* /app/tests/*
COPY pyproject.toml ./
COPY src/ ./src/
COPY tests/ ./tests/

ENV PYTHONPATH=/app/src
CMD ["python", "-m", "abstract_ops.server"]
