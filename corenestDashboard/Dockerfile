FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5050

CMD ["gunicorn", "--workers", "4", "--threads", "2", "--bind", "0.0.0.0:5050", "--timeout", "120", "--access-logfile", "-", "app:app"]
