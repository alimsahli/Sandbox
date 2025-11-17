# Use a slim Python base image for smaller size and security
FROM python:3.10-slim

# Set environment variables for non-buffered output and Flask configuration
ENV PYTHONUNBUFFERED 1
ENV FLASK_APP app.py
ENV FLASK_RUN_HOST 0.0.0.0

# Set the working directory inside the container
WORKDIR /app

# Install Flask and Gunicorn directly since requirements.txt is not used.
# Gunicorn is crucial for running Flask in a production-like environment (like Jenkins/Docker).
RUN pip install --no-cache-dir Flask gunicorn

# Copy ALL project files (including app.py, static/, templates/, etc.) 
# from the Jenkins workspace into the container's /app directory
COPY . .

# Expose the port where Gunicorn will listen
EXPOSE 8080

# Command to run the application using Gunicorn.
# This assumes your Flask application instance inside app.py is named 'app'.
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "app:app"]