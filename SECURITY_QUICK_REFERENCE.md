# Trivial Security Fixes - Quick Reference

## What Was Fixed

Four critical vulnerabilities that were trivial to exploit have been secured:

### 1️⃣ **No Authentication** → ✅ JWT Bearer Tokens Required

**Before:** Anyone could access all data
```bash
curl http://localhost:8000/api/v1/alerts/  # Works (BAD!)
```

**After:** Authentication required on all protected endpoints
```bash
# Step 1: Login to get token
TOKEN=$(curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password123"}' \
  | jq -r '.access_token')

# Step 2: Use token in requests
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/alerts/
```

**Demo Credentials:**
- User: `user` / Password: `password123`
- Admin: `admin` / Password: `admin123`

---

### 2️⃣ **SQL Injection via Filters** → ✅ Input Validation

**Before:** Unvalidated strings allowed SQL injection
```bash
# Attack: SQL injection
curl "http://localhost:8000/api/v1/alerts/?source_ip=1.1.1.1' OR '1'='1"
# Result: Returns all alerts
```

**After:** All inputs validated with Pydantic
```bash
# IP is validated as real IP address
curl "http://localhost:8000/api/v1/alerts/?source_ip=192.168.1.1" \
  -H "Authorization: Bearer $TOKEN"
# Result: Must be valid IP or validation fails

# Invalid IP attempt
curl "http://localhost:8000/api/v1/alerts/?source_ip=invalid' OR '1'='1" \
  -H "Authorization: Bearer $TOKEN"
# Result: 422 Unprocessable Entity - "Invalid IP address"
```

**Protected Fields:**
- `source_ip` / `dest_ip` - Must be valid IP addresses
- `source_port` / `dest_port` - Must be 1-65535
- `severity` - Must be one of: critical, high, medium, low
- `score` - Must be 0-100 float
- `alert_type` - Max 100 characters

---

### 3️⃣ **Unrestricted Data Deletion** → ✅ Admin API Key Required

**Before:** Anyone could delete entire database
```bash
curl -X DELETE http://localhost:8000/api/v1/alerts/reset
# Result: 204 No Content - ALL DATA DELETED ☠️
```

**After:** Admin key required
```bash
# Without key: REJECTED
curl -X DELETE http://localhost:8000/api/v1/alerts/reset
# Result: 401 Unauthorized

# With admin key:
curl -X DELETE http://localhost:8000/api/v1/alerts/reset \
  -H "admin-key: admin-key-change-in-production"
# Result: 204 No Content - Only with valid key
```

**Change Admin Key:**
```env
# .env file
ADMIN_API_KEY=your-secure-admin-key-here
```

---

### 4️⃣ **Open CORS Headers** → ✅ Restricted Methods/Headers

**Before:** Any HTTP method from any origin allowed
```
allow_methods=["*"]     # All methods (PUT, DELETE, PATCH, etc.)
allow_headers=["*"]     # All headers allowed
```

**After:** Restricted to safe methods only
```python
allow_methods=["GET", "POST", "OPTIONS"]              # Only safe methods
allow_headers=["Content-Type", "Authorization"]       # Only needed headers
```

---

## 📋 Testing the Fixes

### Setup

```bash
# 1. Install new dependencies
cd backend
pip install -r requirements.txt

# 2. Create .env file
cp .env.example .env

# 3. Update .env with desired values (optional, defaults work for demo)
# Edit backend/.env if needed
```

### Run Demo

```bash
# Option 1: Python demo script
cd ..  # Go back to root
python demo_api_client.py

# Option 2: Manual curl commands
# Get token
TOKEN=$(curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password123"}' \
  | jq -r '.access_token')

# Use token
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/alerts/
```

---

## 🔧 Configuration

### JWT Settings (Development)
```env
# backend/.env
JWT_SECRET=your-secret-key-will-be-auto-generated-if-not-set
JWT_ALGORITHM=HS256
```

### Admin API Key
```env
# backend/.env
ADMIN_API_KEY=admin-key-change-in-production
```

### CORS Origins
```env
# backend/.env
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
```

---

## ⚠️ Production Requirements

Before deploying to production:

- [ ] Change `JWT_SECRET` to a strong random value
  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(32))"
  ```
- [ ] Store secrets in secure location (Kubernetes, Vault, AWS Secrets Manager)
- [ ] Change `ADMIN_API_KEY` to something strong
- [ ] Set `DEBUG=false`
- [ ] Enable HTTPS/TLS
- [ ] Implement proper OAuth2 instead of demo login
- [ ] Add rate limiting (see SECURITY_FIXES.md)
- [ ] Add user database with bcrypt password hashing

---

## 🔄 API Endpoints Reference

### Public (No Auth Required)
- `GET /api/v1/health/` - Health check
- `POST /api/v1/auth/login` - Get JWT token

### Protected (Bearer Token Required)
- `GET /api/v1/alerts/` - List alerts
- `GET /api/v1/alerts/{id}` - Get single alert
- `GET /api/v1/alerts/stats` - Get statistics
- `GET /api/v1/alerts/stream` - Subscribe to real-time alerts (SSE)
- `POST /api/v1/alerts/ingest` - Ingest new alert

### Admin Only (Admin Key Header Required)
- `DELETE /api/v1/alerts/reset` - Delete all alerts (header: `admin-key`)

---

## 📚 Files Modified

1. **New Files:**
   - `backend/app/core/security.py` - JWT authentication utilities
   - `backend/app/api/auth.py` - Login endpoint
   - `.env.example` - Configuration template
   - `SECURITY_FIXES.md` - Detailed security documentation
   - `demo_api_client.py` - Demo script

2. **Modified Files:**
   - `backend/app/core/config.py` - Added JWT and admin key config
   - `backend/app/main.py` - Restricted CORS, added auth router
   - `backend/app/models/alert.py` - Added enums and validators
   - `backend/app/api/alerts.py` - Added authentication to endpoints
   - `backend/requirements.txt` - Added JWT libraries

---

## ✅ Security Checklist

- [x] JWT authentication on protected endpoints
- [x] Input validation (IP addresses, enums, ranges, string lengths)
- [x] Admin-only delete operations
- [x] Restricted CORS headers
- [x] Enum-based severity filtering
- [x] Port number validation (1-65535)
- [x] Score validation (0-100)
- [ ] Rate limiting (TODO - medium priority)
- [ ] HTTPS/TLS (TODO - medium priority)
- [ ] PII sanitization from logs (TODO - medium priority)
- [ ] RBAC/permission system (TODO - advanced)

---

## 🆘 Troubleshooting

### "Invalid authentication credentials"
- Check token format: `Authorization: Bearer <token>`
- Login first to get token: `POST /api/v1/auth/login`
- Token may have expired (24 hours)

### "Invalid IP address"
- Ensure IP is valid: `192.168.1.1` (IPv4) or `::1` (IPv6)
- IPv6 must be properly formatted

### "Invalid token in admin-key header"
- Use correct admin key from `.env`
- Default in example: `admin-key-change-in-production`

### Unauthorized (401) on protected endpoint
- Must provide valid Bearer token
- Login first: `POST /api/v1/auth/login`

---

For detailed security information, see [SECURITY_FIXES.md](SECURITY_FIXES.md)
