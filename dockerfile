FROM python:3.13-slim AS base

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1

COPY requirement.txt .
RUN pip install --no-cache-dir -r requirement.txt

RUN addgroup --system app && adduser --system --ingroup app app

FROM base AS dev

COPY --chown=app:app main.py .
COPY --chown=app:app agent ./agent
COPY --chown=app:app templates ./templates

USER app

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
