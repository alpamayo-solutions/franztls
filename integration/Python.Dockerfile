FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

COPY integration/python_interop.py /opt/python_interop.py
RUN groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin nonroot \
    && install -d -o 65532 -g 65532 -m 0700 /etc/certs

USER 65532:65532
ENTRYPOINT ["python", "/opt/python_interop.py"]
