# Stage 1: Build Stage (Uses a minimal Python image)
FROM python:3.10-slim-buster AS base

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV FLASK_APP app.py
ENV FLASK_RUN_HOST 0.0.0.0

# Set the working directory inside the container
WORKDIR /app

# Copy dependency files and install them
# Using requirements.txt is best practice for dependency management
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port the application runs on
# Flask's default development port is 5000, but 8080 is often used in CI/CD environments
EXPOSE 8080

# Stage 2: Production/Runtime Stage (You can skip this for simplicity if needed, but it's better for security)
# FROM base

# Command to run the application using Gunicorn (a production WSGI server)
# Assuming 'app' is the Flask application instance defined in app.py
# If you don't use Gunicorn, replace this with 'flask run' or 'python app.py'
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "app:app"]