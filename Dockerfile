FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY rules ./rules
COPY samples ./samples
COPY integrations ./integrations
COPY dashboards ./dashboards
COPY docs ./docs

EXPOSE 8000

CMD ["python", "-m", "src.api.run"]