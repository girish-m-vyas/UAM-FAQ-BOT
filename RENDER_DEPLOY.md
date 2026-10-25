# Render deployment settings

Service type: Web Service
Runtime: Node
Build Command: npm install
Start Command: npm start
Health Check Path: /health

Environment variables to create in Render:
- NODE_ENV=production
- SESSION_SECRET=<long random secret>
- ADMIN_USERNAME=<admin username>
- ADMIN_PASSWORD=<strong password>
- ADMIN_NAME=<display name>
- GROQ_API_KEY=<your Groq API key>
- GROQ_MODEL=<Groq model name>
- DATA_DIR=/var/data   # only when using a persistent disk

Do not upload or commit your local .env file.

For persistent operational data on Render, use a paid Web Service and attach a persistent disk:
- Mount Path: /var/data
- Size: 1 GB is more than enough for this JSON-based app initially
Then set DATA_DIR=/var/data.
