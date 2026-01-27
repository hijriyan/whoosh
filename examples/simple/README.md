# simple service

simple service for testing whoosh

## run

Start upstream server:

```bash
uv sync
uv run uvicorn main:app
```

Start whoosh server:

```bash
cargo build -r
RUST_LOG=info ./target/release/simple whoosh.yml
```
