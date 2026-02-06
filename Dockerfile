# Use a lightweight public Python image (no login required)
FROM python:3.11-alpine

# Set working directory inside container
WORKDIR /app

# Copy all necessary files
COPY log_analyzer.py example_auth.log README.md .gitignore /app/

# Set environment variable to prevent Python from buffering stdout
ENV PYTHONUNBUFFERED=1

# Default command to run the analyzer
CMD ["python", "log_analyzer.py"]

