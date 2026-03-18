# Contributing to Ásbrú Plus

Thanks for your interest in contributing. This is a small community fork —
contributions are welcome and the bar is low.

## Before you start

Open an issue first to discuss what you want to change. This avoids
duplicate work and lets us align on the approach before you write code.

## Ground rules

- Be respectful. This is a volunteer project.
- You assert that you have the rights to any code you submit.
- By submitting a PR you agree your contribution is released under GPL-3.

## Making changes

1. Fork the repo and create a branch (`fix/my-bug`, `feat/my-feature`).
2. Make your change. Keep it focused — one thing per PR.
3. Run the test suite: `docker compose run --rm test`
4. If your change affects packaging, also run: `docker compose run --rm build-deb`
5. Update `README.md` if you're changing user-visible behaviour.
6. Open a PR with a clear title describing what changed and why.

## Versioning

We use [SemVer](https://semver.org/). Patch for bug fixes, minor for
new features, major for breaking changes.

## PR title format

```
Fix: short description of what was broken
Add: short description of new feature
Refactor: what changed and why
```
