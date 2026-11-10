FROM python:3.12-alpine

WORKDIR /app
COPY app.py .

EXPOSE 5000

USER nobody

CMD ["python", "-u", "app.py"]
