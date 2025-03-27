FROM python:3.10-slim

# Install system packages for scapy
RUN apt-get update && apt-get install -y tcpdump libpcap-dev iproute2 iputils-ping

# Create workdir
WORKDIR /app

# Copy files
COPY . .

# Install Python deps
RUN pip install --no-cache-dir -r requirements.txt

# Expose shell entrypoint
ENTRYPOINT ["./entrypoint.sh"]

