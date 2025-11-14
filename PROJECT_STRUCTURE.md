# 🍯 Honeypot Project Structure & Progress Report

## 📁 Folder Structure & Purpose

### Root Directory Files

#### Core Honeypot Services
- **`fake_git_repo.py`** - Fake Git repository honeypot service (Port 8001)
- **`fake_cicd_runner.py`** - Fake CI/CD runner honeypot service (Port 8002)
- **`logging_server.py`** - ⚠️ DUPLICATE (use `logging_server/logging_server.py` instead)
- **`start_honeypot.py`** - ⚠️ OLD startup script (use `start_unified_honeypot.py` instead)
- **`start_unified_honeypot.py`** - ✅ **MAIN** unified startup script for all services

#### Machine Learning System
- **`ml_training_system.py`** - ✅ **MAIN** ML model training system
- **`ml_prediction_system.py`** - ✅ **MAIN** real-time ML prediction system
- **`ml_honeypot_integration.py`** - ✅ ML integration with honeypot services
- **`simple_ml_training.py`** - ⚠️ DUPLICATE (simplified version, not used)
- **`simple_ml_prediction.py`** - ⚠️ DUPLICATE (simplified version, not used)
- **`working_ml_system.py`** - ⚠️ DUPLICATE (old working version)
- **`complete_honeypot_ml_system.py`** - ⚠️ DUPLICATE (uses working_ml_system.py)

#### Testing & Documentation
- **`test_client.py`** - Test client for honeypot services
- **`test_integration.py`** - Integration tests for unified system
- **`HONEYPOT_README.md`** - Original honeypot documentation
- **`ML_HONEYPOT_README.md`** - ML system documentation
- **`UNIFIED_HONEYPOT_README.md`** - Unified system documentation

#### Configuration & Data
- **`requirements.txt`** - Python dependencies for honeypot services
- **`ml_requirements.txt`** - Python dependencies for ML system
- **`honeypot.db`** - SQLite database (auto-generated, contains attack logs)
- **`ml_alerts.jsonl`** - ML alert logs (generated at runtime)

---

### 📂 `Honeypot/` Folder
**Purpose:** Phase 2 consolidated honeypot services

- **`honeypot_services.py`** - Combined Git & CI/CD service (Port 8000)
- **`start_honeypot.py`** - Service-specific startup script
- **`test_honeypot.py`** - Service-specific tests
- **`static/`** - Fake files to lure attackers:
  - `secrets.yml` - Fake secrets
  - `env_file` - Fake environment variables
  - `config.json` - Fake configuration
  - `README.md` - Fake documentation
- **`venv/`** - Python virtual environment (can be regenerated)
- **`requirements.txt`** - Service dependencies

---

### 📂 `logging_server/` Folder
**Purpose:** Phase 3 centralized logging system

- **`logging_server.py`** - ✅ **MAIN** enhanced logging server (Port 5000)
- **`start_logging_server.py`** - Logging server startup script
- **`send_test_log.py`** - Test script for logging server
- **`venv/`** - Python virtual environment (can be regenerated)
- **`requirements.txt`** - Logging server dependencies

---

### 📂 `db1/` Folder
**Purpose:** Frontend React dashboard (Kibana-style visualization)

- **`src/`** - React source code:
  - `App.js` - Main dashboard component
  - `App.css` - Dashboard styles
  - `index.js` - React entry point
  - `index.css` - Global styles
- **`public/`** - Public assets:
  - `index.html` - HTML template
- **`package.json`** - Node.js dependencies and scripts
- **`node_modules/`** - Node.js packages (can be regenerated with `npm install`)

**To start:** `cd db1 && npm start` (runs on http://localhost:3000)

---

### 📂 `csv/CSV Files/` Folder
**Purpose:** UNSW-NB15 dataset for ML training

- **`Training and Testing Sets/`** - Main dataset:
  - `UNSW_NB15_training-set.csv` - Training data
  - `UNSW_NB15_testing-set.csv` - Testing data
- **`NUSW-NB15_features.csv`** - Feature descriptions
- **`NUSW-NB15_GT.csv`** - Ground truth labels
- **`UNSW-NB15_*.csv`** - Additional dataset files (1-4)
- **`UNSW-NB15_LIST_EVENTS.csv`** - Event list
- **`The UNSW-NB15 description.pdf`** - Dataset documentation

---

### 📂 `ml_models/` Folder
**Purpose:** Trained ML models and preprocessing objects

- **`best_model_info.json`** - Best model metadata
- **`model_info.json`** - Model information
- **`feature_columns.json`** - Feature column names
- **`*.pkl`** - Trained models and encoders:
  - `randomforest_model.pkl` - Random Forest model
  - `logisticregression_model.pkl` - Logistic Regression model
  - `model.pkl` - Best model
  - `scaler.pkl`, `standard_scaler.pkl` - Data scalers
  - `*_encoder.pkl` - Label encoders (attack_cat, proto, service, state)

---

### 📂 `ml_results/` Folder
**Purpose:** ML training results and reports

- **`training_report.md`** - Training results report
- **`dataset_stats.json`** - Dataset statistics
- **`feature_importance.csv`** - Feature importance analysis

---

### 📂 `ml_plots/` Folder
**Purpose:** ML visualization plots (generated during training)

---

### 📂 `__pycache__/` Folder
**Purpose:** Python bytecode cache (auto-generated, can be deleted)

---

## 🚀 Current System Status

### ✅ Completed Components

1. **Honeypot Services** (Phase 1-2)
   - ✅ Fake Git Repository (Port 8001)
   - ✅ Fake CI/CD Runner (Port 8002)
   - ✅ Consolidated Honeypot (Port 8000)
   - ✅ All services log to centralized server

2. **Logging System** (Phase 3)
   - ✅ Centralized logging server (Port 5000)
   - ✅ SQLite database storage
   - ✅ GeoIP enrichment
   - ✅ Statistics and analytics endpoints

3. **Machine Learning System** (Phase 4)
   - ✅ ML model training pipeline
   - ✅ Real-time prediction system
   - ✅ Honeypot-ML integration
   - ✅ Trained models stored in `ml_models/`

4. **Frontend Dashboard** (Phase 5)
   - ✅ React-based Kibana-style dashboard
   - ✅ Interactive charts and visualizations
   - ✅ Real-time data display

### 🔄 Integration Status

- ✅ Honeypot services → Logging server
- ✅ ML system → Honeypot logs
- ⚠️ Frontend → Backend API (needs connection to logging server)

### 📊 System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  HONEYPOT SYSTEM                        │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Frontend (db1/)          Port 3000                      │
│  ┌─────────────────┐                                     │
│  │ React Dashboard │                                     │
│  └────────┬────────┘                                     │
│           │                                              │
│  Honeypot Services                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Git Repo     │  │ CI/CD Runner │  │ Consolidated │  │
│  │ Port 8001    │  │ Port 8002    │  │ Port 8000    │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                 │                  │           │
│         └─────────────────┼──────────────────┘           │
│                           │                              │
│  Logging Server           │                              │
│  ┌────────────────────────▼──────────────┐              │
│  │  Port 5000                            │              │
│  │  • Log ingestion                      │              │
│  │  • GeoIP enrichment                   │              │
│  │  • SQLite database                    │              │
│  └──────────────┬───────────────────────┘              │
│                 │                                        │
│  ML System      │                                        │
│  ┌──────────────▼──────────────┐                        │
│  │  • Real-time prediction     │                        │
│  │  • Attack detection         │                        │
│  │  • Alert generation         │                        │
│  └─────────────────────────────┘                        │
└─────────────────────────────────────────────────────────┘
```

## 🎯 How to Start the System

### Option 1: Unified System (Recommended)
```bash
python start_unified_honeypot.py
```
Starts all honeypot services + logging server together.

### Option 2: Individual Services
```bash
# Terminal 1: Logging Server
cd logging_server
python logging_server.py

# Terminal 2: Honeypot Services
python fake_git_repo.py &
python fake_cicd_runner.py &
python Honeypot/honeypot_services.py

# Terminal 3: ML Integration
python ml_honeypot_integration.py

# Terminal 4: Frontend
cd db1
npm start
```

## 📝 Next Steps

1. **Connect Frontend to Backend**
   - Update React app to fetch data from logging server API
   - Add real-time data updates

2. **Production Deployment**
   - Add authentication to APIs
   - Implement rate limiting
   - Set up proper error handling

3. **Enhanced Features**
   - Real-time alert notifications
   - Advanced analytics
   - Export capabilities

---

**Last Updated:** $(date)
**Project Status:** ✅ Core system complete, frontend needs backend integration

