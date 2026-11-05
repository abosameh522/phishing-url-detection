.PHONY: all data train eval gates test api clean
all: data train eval gates

data:
	uv run python scripts/prepare_data.py
train:
	uv run python scripts/train.py

eval:
	uv run python scripts/evaluate.py

gates: test
	uv run python scripts/gates.py

test:
	uv run pytest

api:
	uv run uvicorn phishing_url_detection.api:app --host 127.0.0.1 --port 8000
clean:
	rm -rf .venv
