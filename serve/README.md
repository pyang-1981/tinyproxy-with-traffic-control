# Test File Server

A simple Python HTTP server that serves a 1GB test file for testing proxy bandwidth limits and download speeds.

## Build

```bash
docker build -t test-fileserver:latest .
```

## Run

```bash
# Run on port 8080
docker run -d -p 8080:8080 --name fileserver test-fileserver:latest

# Or run on a different port
docker run -d -p 9000:8080 --name fileserver test-fileserver:latest
```

## Usage

Once running, you can:

1. **Browse**: Open http://localhost:8080 in your browser
2. **Download**: Click the link to download the 1GB test file
3. **Test with curl**: `curl -O http://localhost:8080/testfile-1gb.bin`
4. **Test through proxy**: 
   ```bash
   curl -x http://localhost:8888 -O http://fileserver:8080/testfile-1gb.bin
   ```

## Testing Bandwidth Limits

Use this server to test tinyproxy's traffic control rules:

```bash
# Start the file server
docker run -d -p 8080:8080 --name fileserver test-fileserver:latest

# Download through tinyproxy with bandwidth limit
time curl -x http://localhost:8888 http://localhost:8080/testfile-1gb.bin -o /tmp/test.bin

# Monitor download speed
curl -x http://localhost:8888 http://localhost:8080/testfile-1gb.bin -o /tmp/test.bin -w "Speed: %{speed_download} bytes/sec\n"
```

## Kubernetes Deployment

Deploy alongside tinyproxy in Kubernetes:

```bash
kubectl run fileserver --image=test-fileserver:latest --port=8080
kubectl expose pod fileserver --port=8080 --target-port=8080
```

Then test through tinyproxy:
```bash
kubectl exec -it <tinyproxy-pod> -- curl http://fileserver:8080/testfile-1gb.bin -o /tmp/test.bin
```

## File Details

- **File**: `/app/testfile-1gb.bin`
- **Size**: 1 GB (1,073,741,824 bytes)
- **Content**: Zero-filled (created with `dd if=/dev/zero`)
- **Server**: Python 3.11 built-in HTTP server

## Clean Up

```bash
docker stop fileserver
docker rm fileserver
```
