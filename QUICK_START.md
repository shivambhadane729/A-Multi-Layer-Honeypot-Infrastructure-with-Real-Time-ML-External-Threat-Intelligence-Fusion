# 🚀 Quick Start Guide

## Starting the Complete System

### Step 1: Start the Backend (Logging Server)

Open a **new terminal** and run:

```bash
cd logging_server
pip install -r requirements.txt
python logging_server.py
```

You should see:
```
📊 Starting Honeypot Logging Server...
✅ Database initialized successfully
🚀 Starting Flask server on 0.0.0.0:5000...
```

**Keep this terminal open!** The server must be running for the frontend to work.

### Step 2: Start the Frontend

Open **another terminal** and run:

```bash
cd db1
npm install  # Only needed first time
npm start
```

The frontend will open at `http://localhost:3000`

---

## ✅ What's Fixed

1. **React Router Warnings** - Added future flags to suppress deprecation warnings
2. **Database Path** - Logging server now finds database in root or logging_server folder
3. **CORS Enabled** - Backend allows frontend requests

---

## 🔧 Troubleshooting

### "Connection Refused" Errors

**Problem:** Frontend can't connect to backend

**Solution:**
1. Make sure the logging server is running (Step 1)
2. Check that it's running on port 5000
3. Verify no firewall is blocking the connection

### "Module not found" Errors

**Problem:** Missing npm packages

**Solution:**
```bash
cd db1
npm install
```

### "flask-cors not found"

**Problem:** Missing Python package

**Solution:**
```bash
cd logging_server
pip install flask-cors
```

---

## 📊 Testing the Connection

Once both servers are running:

1. Open browser to `http://localhost:3000`
2. Check browser console - should see no connection errors
3. Navigate to different pages using the hamburger menu
4. Data should load (may be empty if no logs exist yet)

---

## 🎯 Next Steps

1. **Generate Some Test Data:**
   ```bash
   cd logging_server
   python send_test_log.py
   ```

2. **Or Start Honeypot Services:**
   ```bash
   python start_unified_honeypot.py
   ```

3. **View Data in Dashboard:**
   - Go to `http://localhost:3000`
   - Check Dashboard, Live Events, Analytics, etc.

---

**Status:** ✅ Ready to use!

