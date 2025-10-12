# Multiple Alerts Files Configuration Guide

## 📁 **Yes, you need to add volume mounts for each additional alerts file!**

### **Current Setup (Single File):**
```yaml
volumes:
  - /var/ossec/logs/alerts/alerts.json:/var/ossec/logs/alerts/alerts.json:ro
```

### **Multiple Files Setup:**

#### **1. Update Environment Variables:**
```yaml
environment:
  # Comment out single file
  # ALERTS_FILE: /var/ossec/logs/alerts/alerts.json
  
  # Enable multiple files
  ALERTS_FILES: /var/ossec/logs/alerts/alerts.json,/var/ossec/logs/alerts/alerts2.json,/var/ossec/logs/alerts/alerts3.json
```

#### **2. Add Volume Mounts for Each File:**
```yaml
volumes:
  # File 1
  - /var/ossec/logs/alerts/alerts.json:/var/ossec/logs/alerts/alerts.json:ro
  
  # File 2
  - /var/ossec/logs/alerts/alerts2.json:/var/ossec/logs/alerts/alerts2.json:ro
  
  # File 3
  - /var/ossec/logs/alerts/alerts3.json:/var/ossec/logs/alerts/alerts3.json:ro
  
  # Log directory
  - /var/log/misp-processor:/var/log/misp-processor
```

---

## **🔧 Complete Example Configuration:**

### **For 3 Wazuh Instances:**
```yaml
services:
  wazuh-misp-processor:
    environment:
      # Multiple files configuration
      ALERTS_FILES: /var/ossec/logs/alerts/alerts.json,/var/ossec/logs/alerts/alerts2.json,/var/ossec/logs/alerts/alerts3.json
      
      # Other settings...
      REDIS_HOST: redis
      MISP_URL: https://cti.codesec.in:65534/attributes/restSearch/
      MISP_API_KEY: fCLjfCQHfXTsfsOUOKNplb8CvO2NzPZakPmXecuV
      ALERT_DEDUP_TTL_MINUTES: 30
    
    volumes:
      # Mount all alerts files
      - /var/ossec/logs/alerts/alerts.json:/var/ossec/logs/alerts/alerts.json:ro
      - /var/ossec/logs/alerts/alerts2.json:/var/ossec/logs/alerts/alerts2.json:ro
      - /var/ossec/logs/alerts/alerts3.json:/var/ossec/logs/alerts/alerts3.json:ro
      
      # Log directory
      - /var/log/misp-processor:/var/log/misp-processor
```

---

## **📋 Step-by-Step Setup:**

### **Step 1: Prepare Your Alerts Files**
Make sure your alerts files exist on the host:
```bash
# Check if files exist
ls -la /var/ossec/logs/alerts/
# Should show: alerts.json, alerts2.json, alerts3.json, etc.
```

### **Step 2: Update docker-compose.yml**
1. **Comment out single file environment:**
   ```yaml
   # ALERTS_FILE: /var/ossec/logs/alerts/alerts.json
   ```

2. **Add multiple files environment:**
   ```yaml
   ALERTS_FILES: /var/ossec/logs/alerts/alerts.json,/var/ossec/logs/alerts/alerts2.json,/var/ossec/logs/alerts/alerts3.json
   ```

3. **Add volume mounts for each file:**
   ```yaml
   volumes:
     - /var/ossec/logs/alerts/alerts.json:/var/ossec/logs/alerts/alerts.json:ro
     - /var/ossec/logs/alerts/alerts2.json:/var/ossec/logs/alerts/alerts2.json:ro
     - /var/ossec/logs/alerts/alerts3.json:/var/ossec/logs/alerts/alerts3.json:ro
     - /var/log/misp-processor:/var/log/misp-processor
   ```

### **Step 3: Deploy**
```bash
sudo docker-compose down
sudo docker-compose up -d
```

### **Step 4: Verify**
```bash
# Check container logs
sudo docker logs wazuh-misp-processor | grep "Monitoring"

# Should show:
# 📁 Monitoring 3 alert file(s): /var/ossec/logs/alerts/alerts.json, /var/ossec/logs/alerts/alerts2.json, /var/ossec/logs/alerts/alerts3.json
```

---

## **🎯 Common Use Cases:**

### **Multiple Wazuh Instances:**
```yaml
ALERTS_FILES: /var/ossec/logs/alerts/alerts.json,/var/ossec/logs/alerts/alerts2.json,/var/ossec/logs/alerts/alerts3.json
```

### **Different Alert Types:**
```yaml
ALERTS_FILES: /var/ossec/logs/alerts/alerts.json,/var/ossec/logs/alerts/security-alerts.json,/var/ossec/logs/alerts/network-alerts.json
```

### **Backup Files:**
```yaml
ALERTS_FILES: /var/ossec/logs/alerts/alerts.json,/var/ossec/logs/alerts/alerts-backup.json
```

---

## **⚠️ Important Notes:**

### **File Permissions:**
- Make sure the container can read all files
- Use `:ro` (read-only) for security
- Check file ownership and permissions

### **File Paths:**
- Use absolute paths in both environment and volumes
- Paths must match exactly between `ALERTS_FILES` and volume mounts
- Container paths should be the same as host paths

### **Performance:**
- Each additional file adds minimal overhead
- Processor handles multiple files efficiently
- Maintains 30k IoCs/minute performance

---

## **🔍 Troubleshooting:**

### **File Not Found Error:**
```bash
# Check if files exist
ls -la /var/ossec/logs/alerts/

# Check container can see files
sudo docker exec wazuh-misp-processor ls -la /var/ossec/logs/alerts/
```

### **Permission Denied:**
```bash
# Fix permissions
sudo chmod 644 /var/ossec/logs/alerts/alerts*.json
sudo chown root:root /var/ossec/logs/alerts/alerts*.json
```

### **Container Won't Start:**
```bash
# Check docker-compose syntax
sudo docker-compose config

# Check logs
sudo docker-compose logs wazuh-misp-processor
```

---

## **✅ Summary:**

**Yes, you absolutely need to add volume mounts for each additional alerts file!**

1. **Environment Variable**: `ALERTS_FILES` with comma-separated paths
2. **Volume Mounts**: One volume mount per file
3. **File Permissions**: Ensure container can read all files
4. **Path Consistency**: Host and container paths must match

The processor will monitor all specified files simultaneously and process alerts from any of them!


