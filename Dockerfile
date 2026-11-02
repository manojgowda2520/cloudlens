FROM python:3.12-slim AS base

# CLOUDLENS_HOME holds the pricing cache, the only state the collector keeps.
# Mounting it as a volume turns a cold start from a few hundred throttled Pricing API calls into zero.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CLOUDLENS_HOME=/var/lib/cloudlens

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cloudlens/ ./cloudlens/
COPY pyproject.toml .
RUN pip install --no-cache-dir --no-deps -e .

RUN useradd --system --uid 10001 cloudlens \
    && mkdir -p "$CLOUDLENS_HOME" \
    && chown cloudlens:cloudlens "$CLOUDLENS_HOME"
USER cloudlens

EXPOSE 9101

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:9101/metrics', timeout=4).status==200 else 1)"

ENTRYPOINT ["cloudlens"]
CMD ["run", "-c", "/etc/cloudlens/config.yaml"]
