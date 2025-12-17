#!/bin/bash
# Clean up any processes using Mobius ports

echo "Checking for processes using ports 3000 and 3001..."

PORT_3000=$(lsof -ti :3000 2>/dev/null)
PORT_3001=$(lsof -ti :3001 2>/dev/null)

if [ -n "$PORT_3000" ]; then
    echo "Killing process on port 3000 (PID: $PORT_3000)"
    kill -9 "$PORT_3000"
fi

if [ -n "$PORT_3001" ]; then
    echo "Killing process on port 3001 (PID: $PORT_3001)"
    kill -9 "$PORT_3001"
fi

echo "✓ Ports cleaned"
