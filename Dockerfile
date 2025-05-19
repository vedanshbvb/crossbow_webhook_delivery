FROM python:3.11

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Cloud Run will provide the PORT environment variable
ENV PORT=8080
EXPOSE ${PORT}

# Use gunicorn for production, but fallback to Django's development server if needed
CMD ["sh", "-c", "gunicorn core.wsgi:application --bind 0.0.0.0:${PORT} || python manage.py runserver 0.0.0.0:${PORT}"] 