#!/bin/bash
# Git Repository Setup Script

echo "🚀 Setting up Git repository for Wazuh MISP Processor"

# Initialize git repository
git init

# Add all files
git add .

# Initial commit
git commit -m "Initial commit: Wazuh MISP Processor - Production Ready

- High-performance IoC processor (30k+ alerts/min)
- Log rotation handling for Wazuh 5GB+ files
- Multiple files support
- Circuit breaker protection
- Redis caching with never-stop retry
- Alert and IoC deduplication
- Production-ready Docker setup"

echo "✅ Repository initialized with initial commit"
echo ""
echo "📋 Next steps:"
echo "1. Create repository on GitHub/GitLab"
echo "2. Add remote origin:"
echo "   git remote add origin https://github.com/yourusername/your-repo-name.git"
echo "3. Push to repository:"
echo "   git push -u origin main"
echo ""
echo "🔐 Remember to update MISP credentials in docker-compose.yml before deployment!"
