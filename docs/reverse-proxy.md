# Reverse Proxy Examples

FlowLens has built-in TLS support, but for production deployments you may prefer to use a dedicated reverse proxy for TLS termination, certificate management, and additional security features.

---

## nginx

### Basic TLS Termination

```nginx
server {
    listen 443 ssl http2;
    server_name flowlens.example.com;

    ssl_certificate     /etc/ssl/certs/flowlens.pem;
    ssl_certificate_key /etc/ssl/private/flowlens.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name flowlens.example.com;
    return 301 https://$host$request_uri;
}
```

### With HTTP Basic Auth at the Proxy Layer

If you prefer to handle authentication at the proxy instead of in FlowLens:

```nginx
server {
    listen 443 ssl http2;
    server_name flowlens.example.com;

    ssl_certificate     /etc/ssl/certs/flowlens.pem;
    ssl_certificate_key /etc/ssl/private/flowlens.key;

    # HTTP Basic Auth
    auth_basic           "FlowLens";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Allow the health check endpoint without auth
    location = /healthz {
        auth_basic off;
        proxy_pass http://127.0.0.1:8080;
    }
}
```

Generate the htpasswd file:

```bash
# Install apache2-utils (Debian/Ubuntu) or httpd-tools (RHEL/CentOS)
htpasswd -c /etc/nginx/.htpasswd admin
```

### Rate Limiting API Requests

```nginx
# Define a rate limit zone (10 requests/sec per IP)
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

server {
    listen 443 ssl http2;
    server_name flowlens.example.com;

    ssl_certificate     /etc/ssl/certs/flowlens.pem;
    ssl_certificate_key /etc/ssl/private/flowlens.key;

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Caddy

Caddy automatically provisions TLS certificates via Let's Encrypt. No manual certificate management needed.

### Basic TLS Termination (Automatic HTTPS)

```caddy
flowlens.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

That's it — Caddy handles TLS certificate provisioning, renewal, and HTTPS redirects automatically.

### With HTTP Basic Auth

```caddy
flowlens.example.com {
    basicauth / {
        admin $2a$14$... # bcrypt hash of password
    }

    # Allow health check without auth
    @healthz path /healthz
    route @healthz {
        reverse_proxy 127.0.0.1:8080
    }

    reverse_proxy 127.0.0.1:8080
}
```

Generate a bcrypt hash for the password:

```bash
caddy hash-password --plaintext 'changeme'
```

### With Rate Limiting

```caddy
flowlens.example.com {
    rate_limit {
        zone api {
            key    {remote_host}
            events 10
            window 1s
        }
    }

    reverse_proxy 127.0.0.1:8080
}
```

> **Note:** The `rate_limit` directive requires the [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit) plugin.

---

## Docker Compose with nginx

A complete example with FlowLens behind nginx with automatic TLS (using certbot):

```yaml
services:
  flowlens:
    image: ghcr.io/darkace1998/flowlens:latest
    restart: unless-stopped
    ports:
      - "2055:2055/udp"
      - "4739:4739/udp"
      - "6343:6343/udp"
    # Web port only exposed to nginx, not publicly
    expose:
      - "8080"
    volumes:
      - flowlens-data:/app/data
      - flowlens-captures:/app/captures

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs:/etc/ssl/certs:ro
      - ./private:/etc/ssl/private:ro
    depends_on:
      - flowlens

volumes:
  flowlens-data:
  flowlens-captures:
```
