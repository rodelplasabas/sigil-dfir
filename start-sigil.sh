#!/bin/bash

echo ""
echo "  ========================================"
echo "   SIGIL - DFIR Compromise Assessment Tool"
echo "   v2.2.0"
echo "  ========================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Clear Python bytecode cache
echo "[*] Clearing Python cache..."
find "$SCRIPT_DIR/backend" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
echo "    Done."
echo ""

# Ensure evtx_dump binaries are executable
if [ -d "$SCRIPT_DIR/backend/tools" ]; then
    chmod +x "$SCRIPT_DIR/backend/tools/evtx_dump"* 2>/dev/null
fi
chmod +x "$SCRIPT_DIR/backend/evtx_dump"* 2>/dev/null

# Start backend
echo "[*] Starting SIGIL Backend on port 8001..."
cd "$SCRIPT_DIR/backend"
python3 -m uvicorn main:app --reload --port 8001 &
BACKEND_PID=$!
cd "$SCRIPT_DIR"

sleep 3

# Start frontend
echo "[*] Starting SIGIL Frontend on port 5173..."
cd "$SCRIPT_DIR/frontend"
npm run dev &
FRONTEND_PID=$!
cd "$SCRIPT_DIR"

sleep 3

echo ""
echo "[+] SIGIL is running!"
echo "    Frontend: http://localhost:5173"
echo "    Backend:  http://localhost:8001"
echo ""
echo "[*] Press Ctrl+C to stop SIGIL..."

# Trap Ctrl+C and cleanup
cleanup() {
    echo ""
    echo "[*] Shutting down SIGIL..."

    # Kill the processes we started
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null

    # Kill any remaining processes on the ports
    if command -v lsof &>/dev/null; then
        lsof -ti:8001 | xargs kill -9 2>/dev/null
        lsof -ti:5173 | xargs kill -9 2>/dev/null
    elif command -v fuser &>/dev/null; then
        fuser -k 8001/tcp 2>/dev/null
        fuser -k 5173/tcp 2>/dev/null
    fi

    echo "[+] SIGIL stopped."
    exit 0
}

trap cleanup SIGINT SIGTERM

# Wait for either process to exit
wait $BACKEND_PID $FRONTEND_PID 2>/dev/null
cleanup