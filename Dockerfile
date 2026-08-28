FROM python:3.11-slim

WORKDIR /app

# Install system networking and build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Run training to build artifacts if not present
RUN python train_models.py

# Expose Streamlit default port
EXPOSE 8501

# Run the SOC Dashboard with dynamic PORT support for Railway / Cloud hosts
CMD streamlit run app.py --server.port=${PORT:-8501} --server.address=0.0.0.0 --theme.base=dark
