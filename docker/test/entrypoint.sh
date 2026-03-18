#!/usr/bin/env bash
set -euo pipefail

# Start virtual framebuffer for GTK3 modules that require a display at compile time
Xvfb :99 -screen 0 1280x1024x24 -ac +extension GLX +render -noreset &
XVFB_PID=$!

export DISPLAY=:99

# Give Xvfb a moment to initialize
sleep 0.5

# Run the test suite
exec prove -lrv t/

# (Xvfb will be cleaned up when the container exits)
