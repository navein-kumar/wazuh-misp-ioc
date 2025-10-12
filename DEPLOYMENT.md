# 🚀 Deployment Guide

## Prerequisites
- Docker & Docker Compose installed
- Access to Wazuh alerts.json file
- MISP API credentials

## Quick Deployment

1. **Clone Repository:**
```bash
git clone <your-repo-url>
cd ossec-misp
```

2. **Update MISP Configuration:**
Edit `docker-compose.yml` and update:
```yaml
MISP_URL: https://your-misp-instance.com/attributes/restSearch/
MISP_API_KEY: your-actual-api-key
```

3. **Deploy:**
```bash
sudo docker-compose up --build
```

4. **Verify:**
```bash
sudo docker-compose ps
sudo docker-compose logs -f wazuh-misp-processor
```

## Production Configuration

The system is configured for maximum reliability:
- `restart: always` - Services never stop
- `REDIS_RETRY_ATTEMPTS: 999` - Never give up on Redis
- Circuit breaker protection for MISP API
- Automatic log rotation handling

## Monitoring

Check processing status:
```bash
# Container status
sudo docker-compose ps

# Live logs
sudo docker-compose logs -f wazuh-misp-processor

# Performance stats (every 5 minutes)
sudo docker logs wazuh-misp-processor | grep "Performance Stats"
```

## Troubleshooting

**Container won't start:**
- Check MISP_URL and MISP_API_KEY
- Verify alerts.json file exists and is readable

**Processing stops:**
- Check logs for errors
- Verify MISP API connectivity
- Check file permissions

**High memory usage:**
- Monitor with `docker stats`
- Restart if needed: `sudo docker-compose restart`
