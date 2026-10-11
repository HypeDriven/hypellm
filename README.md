# HypeLLM Router

A self-hosted Rust gateway for routing LLM requests across local and hosted providers, with OpenAI- and Anthropic-compatible APIs, tenant policy, capacity controls and fleet orchestration.

The project documentation lives in the [HTML wiki](spec/index.html). Open `spec/index.html` directly in a browser; navigation and full-text search work offline.

- [Project overview and quick start](spec/overview.html)
- [Using the router](spec/using-the-router.html)
- [Deployment and configuration](spec/deployment.html)
- [Router specification](spec/router-specification.html)
- [Fleet orchestration](spec/orchestration.html)
- [Threat model](spec/threat-model.html)
- [Current limitations](spec/deferred-issues.html)

## Build and verify

Requires Rust 1.85 or newer on Linux. Run from the repository root:

```bash
cargo build --workspace --offline
cargo test --workspace --offline
cargo clippy --workspace --all-targets --offline
cargo run -q -p hypellm-devtools --bin depscan --offline -- --root .
python3 spec/wiki.py check
```

Edit documentation directly in `spec/`, then run `python3 spec/wiki.py update` to refresh the search index. The [wiki home](spec/index.html#reading-and-maintaining-this-wiki) describes the layout and maintenance commands.

## License

[MIT](LICENSE)
