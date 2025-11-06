# AppleEase Development Tasks

# Default shell configuration
set shell := ["bash", "-c"]

# Prevent Python from writing bytecode
export PYTHONDONTWRITEBYTECODE := "1"

# Activate virtual environment (use: just shell)
shell:
    @echo "Activating virtual environment..."
    @bash -c "export PYTHONDONTWRITEBYTECODE=1 && source .venv/bin/activate && exec bash"

# Install dependencies and tool globally
install:
    uv sync
    uv tool uninstall appleease || true
    uv tool install --reinstall -e .

# Run tests (compile check)
test:
    uv run python -m compileall -q src/appleease


# Clean build artifacts
clean:
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    @echo "✓ Build artifacts cleaned"

# Format code (optional - requires black)
fmt:
    uv run --with black black src/composify

# Run linter (optional - requires ruff)
lint:
    uv run --with ruff ruff check src/composify

# Full development setup
dev: clean install
    @echo "✓ Development environment ready"


# Show available commands
help:
    @just --list


