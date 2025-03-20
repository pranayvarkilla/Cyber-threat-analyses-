FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file first, install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project into the container
COPY . /app/

# Set the working directory for the API
WORKDIR /app/api

# Expose port 8000 for the application
EXPOSE 8000

# Run the FastAPI app using Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
