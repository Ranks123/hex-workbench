# Hex Workbench

AI‑assisted web security testing framework for detecting IDOR, authorization bypasses, and object‑level access control issues.

## Features
- 🔄 Mutation replay with intelligent ID mutation
- 👥 Multi‑auth profile replay & cross‑user corroboration
- 🔗 Attack chain engine & endpoint graph memory
- 🧪 Auto exploit replay with stability checking
- 📊 Rich JSON output with risk scoring & narratives
- 🐍 Burp Suite extension for one‑click testing

## Quick Start

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Set environment variables:
 ```bash  
   export GATEWAY_API_KEY="your-secret-key"
   export HEX_ALLOWED_TARGET_HOSTS="target.com"
```
4. Run the gateway: `python3 app.py`
5. Use the Burp extension or send POST requests to `/ingest`

## Example

```bash
curl -X POST http://localhost:5001/ingest \
-H "X-API-Key: your-secret-key" \
-H "Content-Type: application/json" \
-d '{
 "method": "GET",
 "url": "https://target.com/api/user/123",
 "headers": {"Authorization": "Bearer token"},
 "response": "{\"id\":123,\"name\":\"test\"}",
 "status_code": 200
}' 
```


