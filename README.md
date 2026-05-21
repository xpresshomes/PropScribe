# PropScribe — Deploy to Railway

## Quick Deploy

### 1. Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/propscribe.git
git push -u origin main
```

### 2. Deploy on Railway
1. Go to railway.app → New Project → Deploy from GitHub repo
2. Select your propscribe repo
3. Railway auto-detects Node.js and deploys

### 3. Set Environment Variables
In Railway dashboard → Your service → Variables, add:

| Variable | Value |
|---|---|
| GROQ_API_KEY | Your free Groq key from console.groq.com |
| JWT_SECRET | Any random 32+ character string |
| ADMIN_EMAIL | Your admin email |
| ADMIN_PASSWORD | Your admin password |
| NODE_ENV | production |
| DATA_DIR | /data |
| ALLOWED_ORIGINS | https://your-app.up.railway.app |

### 4. Add Persistent Volume (important — keeps your database across deploys)
Railway dashboard → Your service → Volumes → Add Volume
- Mount path: /data

### 5. Custom Domain (optional)
Railway dashboard → Your service → Settings → Domains → Add Custom Domain

## Local Development
```bash
cp .env.example .env
# Fill in .env values
mkdir -p data
npm install
npm start
```
