FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "mcp>=1.9,<2"
COPY payflow_server.py .
EXPOSE 8000
CMD ["python", "payflow_server.py"]
