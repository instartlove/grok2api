FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /app

# Use China mirror for Playwright browser downloads
ENV PLAYWRIGHT_DOWNLOAD_HOST=https://npmmirror.com/mirrors/playwright/

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers
RUN python -m playwright install --with-deps chrome

# Copy the rest of the application
COPY . .

ENV PORT=5200
ENV PYTHONUNBUFFERED=1

EXPOSE 5200

CMD ["python", "app.py"]
