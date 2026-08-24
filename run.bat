@echo off
echo ====================================================
echo Starting SentinelJWT Security Suite & SIEM Dashboard
echo ====================================================

echo [1/2] Starting FastAPI Backend on http://localhost:8000...
start cmd /k "echo Starting Backend... && cd backend && .\venv\Scripts\python.exe -m uvicorn main:app --reload --port 8000"

echo [2/2] Starting Vite Frontend on http://localhost:5173...
start cmd /k "echo Starting Frontend... && cd frontend && npm run dev"

echo SentinelJWT is booting.
echo - FastAPI documentation: http://localhost:8000/docs
echo - Frontend UI Dashboard: http://localhost:5173/
echo ====================================================
pause
