FROM python:3.12-slim

LABEL maintainer="arkanzasfeziii"
LABEL description="Sovereign — Windows & Active Directory Offensive Suite"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sovereign/ sovereign/

ENTRYPOINT ["python", "-m", "sovereign"]
CMD ["--help"]
