FROM python:3.11-slim

WORKDIR /app

COPY main.py .

RUN RUN pip install flask twilio

ENV PORT=8080

CMD ["python", "main.py"]
