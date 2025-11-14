# 🚀 How to Start the Backend Server

## The Problem
The frontend is trying to connect to `http://localhost:5000` but the server isn't running.

## Solution: Start the Logging Server

### Option 1: Using the Batch File (Easiest)
1. Double-click `start_backend.bat` in the root folder
2. A terminal window will open showing the server starting
3. **Keep this window open!** The server must stay running

### Option 2: Manual Start (Recommended)
1. Open a **NEW terminal/command prompt**
2. Navigate to the project:
   ```bash
   cd C:\Users\shiva\Downloads\HONEYPOT
   ```
3. Start the server:
   ```bash
   cd logging_server
   python logging_server.py
   ```
4. You should see:
   ```
   📊 Starting Honeypot Logging Server...
   ✅ Database initialized successfully
   🚀 Starting Flask server on 0.0.0.0:5000...
   ```
5. **Keep this terminal open!** Don't close it.

### Option 3: Using PowerShell
```powershell
cd C:\Users\shiva\Downloads\HONEYPOT\logging_server
python logging_server.py
```

## ✅ Verify It's Working

Once the server starts, test it:

1. Open a browser and go to: `http://localhost:5000/health`
2. You should see JSON response like:
   ```json
   {
     "status": "healthy",
     "service": "Honeypot Logging Server",
     ...
   }
   ```

3. If you see the JSON, the server is running correctly!

## 🔄 Then Refresh Your Frontend

1. Go back to your React app (`http://localhost:3000`)
2. Refresh the page (F5)
3. The connection errors should disappear
4. Pages should load (may be empty if no data exists yet)

## ⚠️ Important Notes

- **Keep the server terminal open** - Closing it stops the server
- The server runs on **port 5000** - Make sure nothing else is using it
- If port 5000 is busy, you'll see an error - close the other application using it

## 🐛 Troubleshooting

### "Port 5000 already in use"
- Another process is using port 5000
- Close other applications or change the port in `logging_server.py`

### "Module not found: flask_cors"
- Install it: `pip install flask-cors`

### "Database error"
- Make sure you have write permissions in the directory
- The database will be created automatically

---

**Once the server is running, your frontend will connect automatically!**

