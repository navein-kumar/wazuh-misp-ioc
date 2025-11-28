#!/usr/bin/env python3
"""
Efficient file processor that reads alerts.json in chunks
"""

import json
import time
import logging
import os
import requests
import redis
from datetime import datetime
import re
import gzip
import shutil
import signal
import sys
import threading
from typing import Optional, Dict, Any

# Configure logging with environment-based level
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
LOG_LEVEL_MAP = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL,
}

logging.basicConfig(
    level=LOG_LEVEL_MAP.get(LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CircuitBreaker:
    """Circuit breaker pattern for MISP API calls with adaptive backoff"""
    
    def __init__(self, failure_threshold: int = 5, timeout: int = 60, backoff_factor: float = 2.0, max_timeout: int = 604800):
        self.failure_threshold = failure_threshold
        self.base_timeout = timeout
        self.backoff_factor = backoff_factor
        self.max_timeout = max_timeout
        self.current_timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
        self.lock = threading.Lock()
    
    def _update_open_timeout(self):
        # Exponential backoff once we passed threshold
        over_threshold_failures = max(0, self.failure_count - self.failure_threshold + 1)
        self.current_timeout = min(int(self.base_timeout * (self.backoff_factor ** over_threshold_failures)), self.max_timeout)
    
    def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        with self.lock:
            if self.state == 'OPEN':
                elapsed = time.time() - (self.last_failure_time or 0)
                if elapsed > self.current_timeout:
                    self.state = 'HALF_OPEN'
                    logger.info("🔄 Circuit breaker: HALF_OPEN - testing connection")
                else:
                    remaining = int(self.current_timeout - elapsed)
                    logger.warning(f"⚡ Circuit breaker: OPEN - blocking request, retry in ~{max(0, remaining)}s")
                    return None
            
            try:
                result = func(*args, **kwargs)
                if self.state == 'HALF_OPEN':
                    self.state = 'CLOSED'
                    self.failure_count = 0
                    self.current_timeout = self.base_timeout
                    logger.info("✅ Circuit breaker: CLOSED - connection restored")
                return result
            except Exception as e:
                self.failure_count += 1
                self.last_failure_time = time.time()
                
                if self.failure_count >= self.failure_threshold:
                    prev_state = self.state
                    self.state = 'OPEN'
                    self._update_open_timeout()
                    if prev_state != 'OPEN':
                        logger.error(f"⚡ Circuit breaker: OPEN - {self.failure_count} failures, backoff {self.current_timeout}s (max {self.max_timeout}s)")
                    else:
                        logger.error(f"⚡ Circuit breaker: still OPEN - backoff {self.current_timeout}s (max {self.max_timeout}s)")
                
                raise e

class EfficientProcessor:
    """Efficient file processor"""
    
    def __init__(self):
        # Support multiple alerts files
        alerts_files_env = os.getenv('ALERTS_FILES', '')
        if alerts_files_env:
            # Parse comma-separated list of files
            self.alerts_files = [f.strip() for f in alerts_files_env.split(',') if f.strip()]
        else:
            # Fallback to single file for backward compatibility
            single_file = os.getenv('ALERTS_FILE', '/var/ossec/logs/alerts/alerts.json')
            self.alerts_files = [single_file]
        
        # Track position for each file
        self.file_positions = {file_path: 0 for file_path in self.alerts_files}
        self.chunk_size = 1024 * 1024  # 1MB chunks
        
        # Graceful shutdown handling
        self.shutdown_requested = False
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        
        # Redis cache with retry logic
        self.redis_client = self._get_redis_client()
        
        # Circuit breaker for MISP calls
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=int(os.getenv('CIRCUIT_BREAKER_THRESHOLD', '5')),
            timeout=int(os.getenv('CIRCUIT_BREAKER_TIMEOUT', '60')),
            backoff_factor=float(os.getenv('CIRCUIT_BREAKER_BACKOFF_FACTOR', '2.0')),
            max_timeout=int(os.getenv('CIRCUIT_BREAKER_MAX_TIMEOUT', '604800'))  # default 1 week
        )
        
        # MISP settings
        self.misp_url = os.getenv('MISP_URL')
        self.api_key = os.getenv('MISP_API_KEY')
        self.ssl_verify = os.getenv('MISP_SSL_VERIFY', 'false').lower() == 'true'
        
        # Validate required environment variables
        if not self.misp_url:
            raise ValueError("MISP_URL environment variable is required")
        if not self.api_key:
            raise ValueError("MISP_API_KEY environment variable is required")
        
        # Rate limiting - optimized for high volume
        self.rate_limit = float(os.getenv('RATE_LIMIT_SECONDS', '0.01'))  # 10ms between requests (100x faster)
        self.last_request_time = 0
        self.request_count = 0
        self.burst_limit = int(os.getenv('BURST_LIMIT', '100'))  # Allow 100 requests per second
        self.burst_window = float(os.getenv('BURST_WINDOW', '1.0'))  # 1 second window
        
        # Session for HTTP requests
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': self.api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Outage handling
        self.pause_on_misp_outage = os.getenv('PAUSE_ON_MISP_OUTAGE', 'true').lower() == 'true'
        self.misp_probe_interval = int(os.getenv('MISP_PROBE_INTERVAL_SECONDS', '60'))
        self._start_probe_thread_if_needed()
        
        # Cache TTL
        self.cache_ttl = int(os.getenv('CACHE_TTL_HOURS', '24')) * 3600
        
        # Log files
        self.parsed_log_file = os.getenv('LOG_FILE_PARSED', '/var/log/misp-processor/ioc-parsed.log')
        self.matched_log_file = os.getenv('LOG_FILE_MATCHED', '/var/log/misp-processor/ioc-matched.log')
        
        # Log rotation settings
        self.log_rotation_size_mb = int(os.getenv('LOG_ROTATION_SIZE_MB', '1024'))  # 1GB
        self.log_rotation_backup_count = int(os.getenv('LOG_ROTATION_BACKUP_COUNT', '1'))
        
        # IoC patterns
        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
        self.md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        self.sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
        
        # Private IP ranges
        self.private_ip_ranges = [
            (r'^10\.', '10.0.0.0/8'),
            (r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', '172.16.0.0/12'),
            (r'^192\.168\.', '192.168.0.0/16'),
            (r'^127\.', '127.0.0.0/8'),
            (r'^0\.', '0.0.0.0/8'),
        ]
        
        # Common false positives
        self.false_positives = {
            'localhost', 'example.com', 'test.com', 'domain.com',
            'microsoft.com', 'google.com', 'amazon.com', 'apple.com',
            'TCP', 'UDP', 'HTTP', 'HTTPS', 'POST', 'GET', 'PUT', 'DELETE',
            'False', 'True', 'LOCAL', 'TimeWait', 'Idle', 'timestamp',
            'Mozilla', 'Windows', 'Chrome', 'Safari', 'Firefox', 'Edge',
            'EC2AMAZ', 'netstat', 'outbound', 'inbound', 'api', 'www',
            'com', 'org', 'net', 'edu', '200', '300', '400', '500',
            '404', '403', 'https', 'http', 'ftp', 'ssh', 'telnet',
            '2025', '2024', '2023', '2022', '2021', '10.0', '5.0',
            '4.0', '3.0', '2.0', '1.0', 'Win64', 'x64', 'x86', 'ARM',
            'AMD', 'Linux', 'Mac', 'Android', 'iOS'
        }
        
        # Duplicate suppression - track matched IoCs for configurable window
        self.matched_iocs = {}  # {ioc_value: last_match_timestamp}
        self.suppression_window = int(os.getenv('SUPPRESSION_WINDOW_MINUTES', '10')) * 60  # Convert minutes to seconds
        
        # Alert deduplication - track processed alerts to prevent duplicates
        self.processed_alerts = {}  # {alert_id: timestamp}
        self.alert_dedup_ttl = int(os.getenv('ALERT_DEDUP_TTL_MINUTES', '30')) * 60  # Convert minutes to seconds
        
        # Performance metrics
        self.metrics = {
            'alerts_processed': 0,
            'alerts_duplicated': 0,
            'iocs_extracted': 0,
            'misp_queries': 0,
            'cache_hits': 0,
            'start_time': time.time()
        }
    
    def _signal_handler(self, signum, frame):
        """Handle graceful shutdown signals"""
        logger.info(f"🛑 Received signal {signum}, initiating graceful shutdown...")
        self.shutdown_requested = True
    
    def _get_redis_client(self) -> Optional[redis.Redis]:
        """Get Redis client with retry logic"""
        max_retries = int(os.getenv('REDIS_RETRY_ATTEMPTS', '3'))
        retry_delay = float(os.getenv('REDIS_RETRY_DELAY', '2.0'))
        
        for attempt in range(max_retries):
            try:
                client = redis.Redis(
                    host=os.getenv('REDIS_HOST', 'redis'),
                    port=int(os.getenv('REDIS_PORT', '6379')),
                    db=int(os.getenv('REDIS_DB', '0')),
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True
                )
                # Test connection
                client.ping()
                logger.info(f"✅ Redis connected successfully (attempt {attempt + 1})")
                return client
            except (redis.ConnectionError, redis.TimeoutError) as e:
                if attempt == max_retries - 1:
                    logger.error(f"❌ Redis connection failed after {max_retries} attempts: {e}")
                    return None
                logger.warning(f"⚠️ Redis connection failed (attempt {attempt + 1}), retrying in {retry_delay}s: {e}")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
        
        return None
    
    def health_check(self) -> Dict[str, Any]:
        """Get health status of the processor"""
        current_time = time.time()
        uptime = current_time - self.metrics['start_time']
        
        # Check Redis connectivity
        redis_healthy = False
        if self.redis_client:
            try:
                self.redis_client.ping()
                redis_healthy = True
            except:
                redis_healthy = False
        
        # Check file accessibility for all files
        files_accessible = {}
        for file_path in self.alerts_files:
            files_accessible[file_path] = os.path.exists(file_path)
        
        all_files_accessible = all(files_accessible.values())
        
        # Calculate processing rate
        processing_rate = self.metrics['alerts_processed'] / (uptime / 60) if uptime > 0 else 0
        
        return {
            'status': 'healthy' if redis_healthy and all_files_accessible else 'unhealthy',
            'uptime_seconds': uptime,
            'redis_connected': redis_healthy,
            'files_accessible': files_accessible,
            'all_files_accessible': all_files_accessible,
            'circuit_breaker_state': self.circuit_breaker.state,
            'file_positions': self.file_positions.copy(),
            'processing_rate_alerts_per_minute': processing_rate,
            'metrics': self.metrics.copy()
        }
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        for pattern, _ in self.private_ip_ranges:
            if re.match(pattern, ip):
                return True
        return False
    
    def is_false_positive(self, value: str) -> bool:
        """Check if value is a common false positive"""
        return value.lower() in self.false_positives
    
    def is_alert_duplicate(self, alert_id: str) -> bool:
        """Check if alert is a duplicate (already processed within TTL)"""
        current_time = time.time()
        
        # Clean up old entries (older than TTL)
        expired_alerts = []
        for alert_id_key, timestamp in self.processed_alerts.items():
            if current_time - timestamp > self.alert_dedup_ttl:
                expired_alerts.append(alert_id_key)
        
        for alert_id_key in expired_alerts:
            del self.processed_alerts[alert_id_key]
        
        # Check if this alert was processed recently
        if alert_id in self.processed_alerts:
            time_since_last = current_time - self.processed_alerts[alert_id]
            if time_since_last < self.alert_dedup_ttl:
                return True
        
        # Record this alert
        self.processed_alerts[alert_id] = current_time
        return False
    
    def should_suppress_duplicate(self, ioc_value: str) -> bool:
        """Check if IoC match should be suppressed (already matched within 10 minutes)"""
        current_time = time.time()
        
        # Clean up old entries (older than suppression window)
        expired_iocs = []
        for ioc, timestamp in self.matched_iocs.items():
            if current_time - timestamp > self.suppression_window:
                expired_iocs.append(ioc)
        
        for ioc in expired_iocs:
            del self.matched_iocs[ioc]
        
        # Check if this IoC was matched recently
        if ioc_value in self.matched_iocs:
            time_since_last = current_time - self.matched_iocs[ioc_value]
            if time_since_last < self.suppression_window:
                return True
        
        # Record this match
        self.matched_iocs[ioc_value] = current_time
        return False
    
    def get_suppression_stats(self) -> dict:
        """Get statistics about duplicate suppression"""
        current_time = time.time()
        active_suppressions = 0
        
        for ioc, timestamp in self.matched_iocs.items():
            if current_time - timestamp < self.suppression_window:
                active_suppressions += 1
        
        return {
            'total_tracked_iocs': len(self.matched_iocs),
            'active_suppressions': active_suppressions,
            'suppression_window_minutes': self.suppression_window / 60
        }
    
    def extract_iocs(self, text: str) -> list:
        """Extract IoCs from text"""
        iocs = []
        
        # Extract IPs
        ips = self.ip_pattern.findall(text)
        for ip in ips:
            if not self.is_private_ip(ip) and not self.is_false_positive(ip):
                iocs.append({
                    'value': ip,
                    'type': 'ip-dst',
                    'confidence': 0.9
                })
                logger.info(f"🌐 Public IP Found: {ip}")
        
        # Extract domains
        domains = self.domain_pattern.findall(text)
        for domain in domains:
            if not self.is_false_positive(domain) and len(domain) >= 8:
                iocs.append({
                    'value': domain,
                    'type': 'domain',
                    'confidence': 0.8
                })
                logger.info(f"🎯 Domain Found: {domain}")
        
        # Extract hashes
        md5_hashes = self.md5_pattern.findall(text)
        for hash_val in md5_hashes:
            iocs.append({
                'value': hash_val.upper(),
                'type': 'md5',
                'confidence': 0.9
            })
            logger.info(f"🔐 MD5 Hash Found: {hash_val}")
        
        sha256_hashes = self.sha256_pattern.findall(text)
        for hash_val in sha256_hashes:
            iocs.append({
                'value': hash_val.upper(),
                'type': 'sha256',
                'confidence': 0.9
            })
            logger.info(f"🔐 SHA256 Hash Found: {hash_val}")
        
        return iocs
    
    def is_cached(self, ioc_value: str) -> bool:
        """Check if IoC is already cached"""
        if not self.redis_client:
            return False
        
        try:
            cache_key = f"ioc:{ioc_value}"
            return self.redis_client.exists(cache_key)
        except (redis.ConnectionError, redis.TimeoutError):
            logger.warning("⚠️ Redis connection lost, cache check failed")
            return False
    
    def cache_ioc(self, ioc_value: str, result: dict):
        """Cache IoC result"""
        if not self.redis_client:
            return
        
        try:
            cache_key = f"ioc:{ioc_value}"
            self.redis_client.setex(
                cache_key,
                self.cache_ttl,
                json.dumps(result)
            )
        except (redis.ConnectionError, redis.TimeoutError):
            logger.warning("⚠️ Redis connection lost, cache write failed")
    
    def get_cached_result(self, ioc_value: str) -> dict:
        """Get cached IoC result"""
        if not self.redis_client:
            return {}
        
        try:
            cache_key = f"ioc:{ioc_value}"
            cached = self.redis_client.get(cache_key)
            if cached:
                self.metrics['cache_hits'] += 1
                return json.loads(cached)
            return {}
        except (redis.ConnectionError, redis.TimeoutError):
            logger.warning("⚠️ Redis connection lost, cache read failed")
            return {}
    
    def has_misp_match(self, misp_result: dict) -> bool:
        """Check if MISP result contains actual matches"""
        if not misp_result or 'response' not in misp_result:
            return False
        
        response_data = misp_result['response']
        if isinstance(response_data, dict) and 'Attribute' in response_data:
            attributes = response_data['Attribute']
            return isinstance(attributes, list) and len(attributes) > 0
        elif isinstance(response_data, list):
            return len(response_data) > 0
        
        return False

    def _probe_misp(self):
        """Lightweight probe to test MISP availability for auto-resume."""
        try:
            def _probe():
                # Minimal request to check connectivity; small timeout
                resp = self.session.get(self.misp_url, params={'limit': 1}, verify=self.ssl_verify, timeout=5)
                if resp.status_code != 200:
                    raise Exception(f"Probe status {resp.status_code}")
                return True
            self.circuit_breaker.call(_probe)
        except Exception:
            # Swallow exceptions; circuit breaker handles state
            pass

    def _probe_loop(self):
        while not self.shutdown_requested:
            if self.circuit_breaker.state == 'OPEN':
                self._probe_misp()
            time.sleep(self.misp_probe_interval)

    def _start_probe_thread_if_needed(self):
        if self.pause_on_misp_outage:
            t = threading.Thread(target=self._probe_loop, daemon=True)
            t.start()
    
    def rate_limit_check(self):
        """Apply smart rate limiting - only for burst protection"""
        current_time = time.time()
        
        # Reset burst counter if window has passed
        if current_time - self.last_request_time > self.burst_window:
            self.request_count = 0
        
        # Only apply rate limiting if we're hitting burst limit
        if self.request_count >= self.burst_limit:
            sleep_time = self.burst_window - (current_time - self.last_request_time)
            if sleep_time > 0:
                time.sleep(sleep_time)
                self.request_count = 0
        
        # Minimal delay between requests (100ms)
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit:
            time.sleep(self.rate_limit - time_since_last)
        
        self.last_request_time = time.time()
        self.request_count += 1
    
    def _query_misp_internal(self, ioc_value: str, ioc_type: str) -> dict:
        """Internal MISP query method (used by circuit breaker)"""
        # Apply rate limiting
        self.rate_limit_check()
        
        # Query MISP - Use flexible search without type restriction
        params = {
            'value': ioc_value,
            'limit': 10
        }
        
        logger.info(f"🔍 MISP Query: {ioc_value} (type: {ioc_type})")
        response = self.session.get(
            self.misp_url,
            params=params,
            verify=self.ssl_verify,
            timeout=30
        )
        
        if response.status_code == 200:
            logger.info(f"✅ MISP Connected: API Key working, Status: {response.status_code}")
            result = response.json()
            
            # Cache the result
            self.cache_ioc(ioc_value, result)
            
            return result
        else:
            logger.error(f"❌ MISP API Error: Status {response.status_code}")
            raise Exception(f"MISP API returned status {response.status_code}")
    
    def query_misp(self, ioc_value: str, ioc_type: str) -> dict:
        """Query MISP for IoC with circuit breaker protection"""
        # Check cache first
        if self.is_cached(ioc_value):
            logger.info(f"📋 Cache Hit: {ioc_value}")
            return self.get_cached_result(ioc_value)
        
        # Use circuit breaker to protect against MISP failures
        try:
            result = self.circuit_breaker.call(self._query_misp_internal, ioc_value, ioc_type)
            if result is None:
                logger.warning(f"⚡ Circuit breaker blocked MISP query for {ioc_value}")
                return {}
            
            self.metrics['misp_queries'] += 1
            return result
            
        except Exception as e:
            logger.error(f"❌ MISP Query Failed: {e}")
            return {}
    
    def log_rotation(self, log_file):
        """Rotate log file when it reaches the size limit"""
        try:
            if not os.path.exists(log_file):
                return
            
            # Check file size
            file_size_mb = os.path.getsize(log_file) / (1024 * 1024)
            
            if file_size_mb >= self.log_rotation_size_mb:
                logger.info(f"🔄 Log rotation triggered for {log_file} (size: {file_size_mb:.2f}MB)")
                
                # Create timestamp for rotated file
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                rotated_file = f"{log_file}.{timestamp}.gz"
                
                # Compress and move the current log file
                with open(log_file, 'rb') as f_in:
                    with gzip.open(rotated_file, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                # Remove the original file
                os.remove(log_file)
                
                # Clean up old rotated files
                self.cleanup_old_logs(log_file)
                
                logger.info(f"✅ Log rotated: {rotated_file}")
                
        except Exception as e:
            logger.error(f"❌ Log rotation failed: {e}")
    
    def cleanup_old_logs(self, log_file):
        """Clean up old rotated log files"""
        try:
            log_dir = os.path.dirname(log_file)
            log_basename = os.path.basename(log_file)
            
            # Find all rotated files for this log
            rotated_files = []
            for file in os.listdir(log_dir):
                if file.startswith(f"{log_basename}.") and file.endswith(".gz"):
                    rotated_files.append(os.path.join(log_dir, file))
            
            # Sort by modification time (newest first)
            rotated_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            
            # Remove excess files
            if len(rotated_files) > self.log_rotation_backup_count:
                for old_file in rotated_files[self.log_rotation_backup_count:]:
                    os.remove(old_file)
                    logger.info(f"🗑️ Removed old log: {old_file}")
                    
        except Exception as e:
            logger.error(f"❌ Log cleanup failed: {e}")
    
    def process_alert(self, alert):
        """Process a single alert"""
        try:
            alert_id = alert.get('id')
            
            # Check for alert deduplication
            if self.is_alert_duplicate(alert_id):
                self.metrics['alerts_duplicated'] += 1
                logger.debug(f"🔇 Duplicate alert suppressed: {alert_id}")
                return
            
            self.metrics['alerts_processed'] += 1
            
            # Extract IoCs
            alert_text = alert.get('full_log', '')
            iocs = self.extract_iocs(alert_text)
            self.metrics['iocs_extracted'] += len(iocs)
            
            if iocs:
                # Log parsed IoCs
                parsed_entry = {
                    'alert_id': alert.get('id'),
                    'iocs': iocs,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                with open(self.parsed_log_file, 'a') as f:
                    f.write(json.dumps(parsed_entry) + '\n')
                
                # Check for log rotation
                self.log_rotation(self.parsed_log_file)
                
                # Process with MISP - Skip if already cached (suppress duplicates)
                misp_results = []
                for ioc in iocs:
                    ioc_value = ioc['value']
                    
                    # Check if IoC is already cached (already processed) - SKIP IT
                    if self.is_cached(ioc_value):
                        logger.info(f"🔇 Suppressed duplicate IoC: {ioc_value}")
                        continue
                    
                    # New IoC, query MISP
                    misp_result = self.query_misp(ioc_value, ioc['type'])
                    if self.has_misp_match(misp_result):
                        misp_results.append({
                            'ioc': ioc,
                            'misp_result': misp_result,
                            'timestamp': datetime.utcnow().isoformat()
                        })
                        logger.info(f"🎯 MISP Match Found: {ioc_value}")
                
                if misp_results:
                    # Log matched IoCs (suppression already handled above)
                    for result in misp_results:
                        ioc_value = result['ioc']['value']
                        
                        try:
                            # Get the first response item safely
                            response_items = result['misp_result'].get('response', [])
                            if isinstance(response_items, list) and len(response_items) > 0:
                                first_item = response_items[0]
                            elif isinstance(response_items, dict):
                                first_item = response_items
                            else:
                                logger.warning(f"⚠️ Unexpected response format for {ioc_value}: {type(response_items)}")
                                continue
                            
                            matched_entry = {
                                'misp': {
                                    'event_id': first_item.get('event_id', ''),
                                    'category': first_item.get('category', ''),
                                    'type': result['ioc']['type'],
                                    'value': ioc_value
                                },
                                'full_alert': alert,
                                'original_rule': alert.get('rule', {}),
                                'original_agent': alert.get('agent', {}),
                                'timestamp': result['timestamp']
                            }
                            
                            with open(self.matched_log_file, 'a') as f:
                                f.write(json.dumps(matched_entry) + '\n')
                                
                            # Check for log rotation
                            self.log_rotation(self.matched_log_file)
                                
                            logger.info(f"✅ Successfully wrote matched log for {ioc_value}")
                        except Exception as e:
                            logger.error(f"❌ Error writing matched log: {e}")
                            import traceback
                            logger.error(f"❌ Traceback: {traceback.format_exc()}")
                
                logger.info(f"📊 Processed alert {alert.get('id')}: {len(iocs)} IoCs, {len(misp_results)} matches")
            
        except Exception as e:
            logger.error(f"❌ Error processing alert: {e}")
            import traceback
            logger.error(f"❌ Traceback: {traceback.format_exc()}")
    
    def read_file_chunks(self, alerts_file):
        """Read file in chunks to avoid memory issues"""
        try:
            last_position = self.file_positions[alerts_file]
            
            # Check if file was rotated (file size is smaller than our last position)
            current_size = os.path.getsize(alerts_file)
            if current_size < last_position:
                logger.info(f"🔄 File rotation detected for {alerts_file}! File size: {current_size}, Last position: {last_position}")
                logger.info("🔄 Resetting position to start of file")
                self.file_positions[alerts_file] = 0
                last_position = 0
            
            # Additional check: if file is very small (likely rotated and recreated)
            if current_size < 1000 and last_position > 1000000:  # File is < 1KB but we were reading from > 1MB
                logger.info(f"🔄 File appears to be recreated after rotation for {alerts_file}! File size: {current_size}, Last position: {last_position}")
                logger.info("🔄 Resetting position to start of new file")
                self.file_positions[alerts_file] = 0
                last_position = 0
            
            with open(alerts_file, 'r') as f:
                f.seek(last_position)
                
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    # Process chunk
                    lines = chunk.split('\n')
                    for line in lines[:-1]:  # Process complete lines
                        if line.strip():
                            try:
                                alert = json.loads(line)
                                # Add source file info to alert
                                alert['_source_file'] = alerts_file
                                self.process_alert(alert)
                            except json.JSONDecodeError as e:
                                logger.warning(f"Failed to parse JSON from {alerts_file}: {e}")
                                continue
                    
                    # Update position
                    self.file_positions[alerts_file] = f.tell()
                    
                    # Minimal delay for high volume processing
                    time.sleep(0.01)
                    
        except FileNotFoundError:
            logger.warning(f"⚠️ Alerts file not found: {alerts_file}. Waiting for file to appear...")
            time.sleep(5)
        except Exception as e:
            logger.error(f"❌ Error reading file {alerts_file}: {e}")
            # Reset position on error to avoid getting stuck
            self.file_positions[alerts_file] = 0
    
    def run(self):
        """Main processing loop"""
        suppression_minutes = self.suppression_window // 60
        dedup_minutes = self.alert_dedup_ttl // 60
        logger.info(f"🚀 Starting efficient file processor with duplicate suppression ({suppression_minutes}min window) and alert deduplication ({dedup_minutes}min TTL)")
        logger.info(f"📁 Monitoring {len(self.alerts_files)} alert file(s): {', '.join(self.alerts_files)}")
        
        last_stats_time = time.time()
        stats_interval = 300  # Show stats every 5 minutes
        
        while not self.shutdown_requested:
            try:
                # If configured, pause processing during MISP outage to avoid losing alerts
                if self.pause_on_misp_outage and self.circuit_breaker.state == 'OPEN':
                    logger.warning("⏸️  Paused due to MISP outage (circuit OPEN). Will auto-resume when healthy.")
                    time.sleep(5)
                    continue
                files_processed = 0
                
                # Process each alerts file
                for alerts_file in self.alerts_files:
                    # Check if file exists
                    if not os.path.exists(alerts_file):
                        logger.warning(f"⚠️ Alerts file not found: {alerts_file}. Waiting...")
                        continue
                    
                    # Check file size
                    current_size = os.path.getsize(alerts_file)
                    last_position = self.file_positions[alerts_file]
                    
                    # Handle file rotation - if file size is smaller than our position, it was rotated
                    if current_size < last_position:
                        logger.info(f"🔄 File rotation detected in main loop for {alerts_file}! File size: {current_size}, Last position: {last_position}")
                        logger.info("🔄 Resetting position to start of file")
                        self.file_positions[alerts_file] = 0
                        last_position = 0
                    
                    # Additional check: if file is very small (likely rotated and recreated)
                    if current_size < 1000 and last_position > 1000000:  # File is < 1KB but we were reading from > 1MB
                        logger.info(f"🔄 File appears to be recreated after rotation in main loop for {alerts_file}! File size: {current_size}, Last position: {last_position}")
                        logger.info("🔄 Resetting position to start of new file")
                        self.file_positions[alerts_file] = 0
                        last_position = 0
                    
                    if current_size > last_position:
                        logger.info(f"📁 File size changed for {alerts_file}: {current_size} bytes (was {last_position})")
                        
                        # Read file in chunks
                        self.read_file_chunks(alerts_file)
                        
                        logger.info(f"📊 Processed {alerts_file} up to position: {self.file_positions[alerts_file]}")
                        files_processed += 1
                
                if files_processed == 0:
                    # No new content in any file, wait (reduced for high volume)
                    time.sleep(1)
                
                # Show stats periodically
                current_time = time.time()
                if current_time - last_stats_time >= stats_interval:
                    stats = self.get_suppression_stats()
                    health = self.health_check()
                    
                    logger.info(f"📈 Performance Stats:")
                    logger.info(f"   📊 Alerts processed: {self.metrics['alerts_processed']}")
                    logger.info(f"   🔇 Alerts duplicated: {self.metrics['alerts_duplicated']}")
                    logger.info(f"   🎯 IoCs extracted: {self.metrics['iocs_extracted']}")
                    logger.info(f"   🔍 MISP queries: {self.metrics['misp_queries']}")
                    logger.info(f"   📋 Cache hits: {self.metrics['cache_hits']}")
                    logger.info(f"   ⚡ Processing rate: {health['processing_rate_alerts_per_minute']:.1f} alerts/min")
                    logger.info(f"   🔄 Circuit breaker: {health['circuit_breaker_state']}")
                    logger.info(f"   📈 Suppression: {stats['active_suppressions']} active, {stats['total_tracked_iocs']} total tracked")
                    
                    last_stats_time = current_time
                    
            except Exception as e:
                logger.error(f"❌ Error in main loop: {e}")
                import traceback
                logger.error(f"❌ Traceback: {traceback.format_exc()}")
                # Reset position on error to avoid getting stuck
                self.last_position = 0
                time.sleep(10)
        
        # Graceful shutdown
        logger.info("🛑 Graceful shutdown completed")
        final_health = self.health_check()
        logger.info(f"📊 Final Stats: {final_health['metrics']}")

def main():
    """Main function"""
    processor = EfficientProcessor()
    processor.run()

if __name__ == "__main__":
    main()
