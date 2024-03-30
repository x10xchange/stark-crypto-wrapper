clean:
	@echo "🧹 Cleaning..."
	cargo clean
	rm -rf *~ dist *.egg-info build target

check:
	@echo "🩺 Checking..."
	cargo check
	poetry check

build:
	@echo "🔨 Building..."
	RUSTFLAGS="-C target-cpu=haswell" maturin build -i 3.9 --sdist --release --zig --strip \
    --target x86_64-unknown-linux-gnu \
    --compatibility manylinux_2_24

sdist:
	@echo "🔨 Building..."
	maturin sdist

develop:
	@echo "⛏️ Building..."
	maturin develop

test:
	@echo "🧪 Testing code: Running pytest"
  # cargo test
	poetry run pytest -vv
	mypy .
