# Simple Python HTTP server for serving a large test file
FROM python:3.11-slim

WORKDIR /app

# Create a 1GB test file
RUN dd if=/dev/zero of=/app/testfile-1gb.bin bs=1M count=1024 && \
    chmod 644 /app/testfile-1gb.bin

# Create a simple HTML index page
RUN echo '<!DOCTYPE html>\n\
<html>\n\
<head>\n\
    <title>Test File Server</title>\n\
    <style>\n\
        body { font-family: Arial, sans-serif; margin: 40px; }\n\
        h1 { color: #333; }\n\
        .file-list { background: #f5f5f5; padding: 20px; border-radius: 5px; }\n\
        a { color: #0066cc; text-decoration: none; font-size: 18px; }\n\
        a:hover { text-decoration: underline; }\n\
        .info { color: #666; margin-top: 10px; }\n\
    </style>\n\
</head>\n\
<body>\n\
    <h1>Test File Server</h1>\n\
    <div class="file-list">\n\
        <p><a href="/testfile-1gb.bin" download>📥 Download testfile-1gb.bin</a></p>\n\
        <p class="info">File size: 1 GB (1,073,741,824 bytes)</p>\n\
    </div>\n\
    <p class="info">Use this file to test proxy bandwidth limits and download speeds.</p>\n\
</body>\n\
</html>' > /app/index.html

EXPOSE 8081

# Use Python's built-in HTTP server
CMD ["python3", "-m", "http.server", "8081", "--bind", "0.0.0.0"]
