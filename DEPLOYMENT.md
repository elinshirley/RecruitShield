# 🚀 DEPLOYMENT GUIDE - RecruitShield

## Step 3: Deploy to Cloud (Heroku / Railway)

### **Option A: Deploy to Heroku (Recommended)**

#### Prerequisites:
- Heroku account (https://heroku.com)
- Heroku CLI installed (https://devcenter.heroku.com/articles/heroku-cli)

#### Step-by-step:

```bash
# 1. Login to Heroku
heroku login

# 2. Create a new Heroku app
heroku create your-app-name

# 3. Create Procfile (tells Heroku how to run the app)
# The Procfile is already created below - just deploy

# 4. Add buildpacks
heroku buildpacks:add heroku/python

# 5. Set environment variables
heroku config:set TELEGRAM_BOT_TOKEN=your_token_here
heroku config:set FLASK_ENV=production

# 6. Deploy
git push heroku main

# 7. View logs
heroku logs --tail

# 8. Open app
heroku open