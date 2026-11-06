# Contributing

Thanks for contributing a plugin or a fix to the ZeroClaw plugin registry.

## How to contribute

[Add a plugin](./README.md#add-a-plugin) in the README covers the required
plugin layout, the build, and the repository validation to run before you open
a pull request. [`docs/ci.md`](./docs/ci.md) explains what pull request
validation checks and how publishing works.

## License

Dual-licensed: [MIT](LICENSE-MIT) OR [Apache 2.0](LICENSE-APACHE). Each
plugin declares its terms in its `Cargo.toml`, and a new plugin uses:

```toml
license = "MIT OR Apache-2.0"
```

The one exception is `plugins/redact-text`, which is Apache 2.0 only because
the reference plugin it is adapted from is. See [`NOTICE`](NOTICE).

Contributions here are covered by the ZeroClaw
[Contributor License Agreement](https://github.com/zeroclaw-labs/zeroclaw/blob/master/docs/book/src/contributing/cla.md)
(CLA). By submitting a contribution you agree to the CLA. No separate
signature is required.

In short, the CLA means:

- You grant ZeroClaw Labs, and everyone who receives the software, a copyright
  license to your contribution under both the MIT License and the Apache
  License 2.0, plus a patent license for any of your patent claims the
  contribution needs.
- You keep the copyright to your contribution, and you can use it in other
  projects under any license.
- Your contribution is your own work, or you have the right to submit it. If
  your employer owns what you write, you have its permission to contribute.
- The CLA grants no right to use the ZeroClaw name or logo.

The CLA text is authoritative; this summary is not. To contribute on behalf of
a company or organization, open an issue titled "Corporate CLA, [Company Name]"
in the [ZeroClaw repository](https://github.com/zeroclaw-labs/zeroclaw/issues)
and a maintainer will follow up.

If your contribution includes code you did not write, keep that code's
copyright and license notices, and say in your pull request where it comes
from and under what license, so it can be credited in [`NOTICE`](NOTICE).
