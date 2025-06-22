# Stop any old processes that might be running
kill -9 $(lsof -t -i:8080 -i:8000 -i:5173) 2>/dev/null

# --- Set up and start the LLM Service ---
echo "Setting up and starting LLM service..."
cd llm_service
./venv/bin/pip install -r requirments.txt --break-system-packages
./venv/bin/python3 app.py &
cd ..

# --- Build and start the Go Backend ---
echo "Building and starting Go backend..."
cd backend
go build -o sentinelsecure_backend .
./sentinelsecure_backend &
cd ..

# --- Start the React Frontend ---
echo "Starting frontend..."
cd frontend
npm install
npm run dev &
cd ..

echo "All services are starting. Please wait a minute for them to load, then try another scan."