.PHONY: check test bench clean

check:
	ruff check .
	python3 -m unittest discover -s tests -p "test_*.py"

test:
	python3 -m unittest discover -s tests -p "test_*.py"

clean:
	rm -rf out_* /tmp/test_out build dist *.egg-info .pytest_cache .ruff_cache
