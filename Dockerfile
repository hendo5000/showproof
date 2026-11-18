FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/data

WORKDIR /app

# run as a non-root user; /data holds the SQLite db and uploaded media
RUN useradd -r -u 1000 app && mkdir /data && chown app /data

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app.py .

USER app
VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/login')"

CMD ["gunicorn", "-b", "0.0.0.0:8000", "-k", "gthread", "--threads", "4", "--timeout", "600", "app:app"]
