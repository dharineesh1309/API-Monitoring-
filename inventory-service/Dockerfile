FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir "setuptools<70"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
