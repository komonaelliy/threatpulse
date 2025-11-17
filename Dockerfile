# Use a lightweight official Python image
FROM python:3.11-alpine

# Set working directory inside container
WORKDIR /app

# Copy project files into the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Default command
CMD ["python3", "src/threatpulse.py"]
