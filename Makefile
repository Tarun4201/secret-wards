.PHONY: check test bench ablation clean

check:
	ruff check .
	python3 -m unittest discover -s tests -p "test_*.py"

test:
	python3 -m unittest discover -s tests -p "test_*.py"

bench:
	python tools/benchmark/benchmark.py

ablation:
	python tools/benchmark/ablation.py

clean:
	rm -rf out_* /tmp/test_out build dist *.egg-info .pytest_cache .ruff_cache
