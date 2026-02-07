FROM python:3.11-slim

WORKDIR /app

COPY main.py .

RUN pip install flask

ENV PORT=8080

CMD ["python", "main.py"]
