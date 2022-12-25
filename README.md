# (V)OPRF : (Verifiable) Oblivious Pseudorandom Functions

[![VOPRF](https://github.com/bytemare/voprf/actions/workflows/ci.yml/badge.svg)](https://github.com/bytemare/voprf/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/voprf.svg)](https://pkg.go.dev/github.com/bytemare/voprf)
[![codecov](https://codecov.io/gh/bytemare/voprf/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/voprf)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fbytemare%2Fvoprf.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fbytemare%2Fvoprf?ref=badge_shield)

Package voprf provides abstracted access to Oblivious Pseudorandom Functions (OPRF) using Elliptic Curves (EC-OPRF).

This implementation supports the OPRF, VOPRF, and POPRF protocols as specified in the latest [internet draft](https://tools.ietf.org/html/draft-irtf-cfrg-voprf).

## Identifiers and bit security

| Identifier            | Bit security |        Implementation         |
|:----------------------|:------------:|:-----------------------------:|
| ristretto255-SHA512   |     128      | github.com/gtank/ristretto255 |
| ~~decaf448-SHAKE256~~ |     224      |        not implemented        |
| P256-SHA256           |     128      | github.com/armfazh/h2c-go-ref |
| P384-SHA384           |     192      | github.com/armfazh/h2c-go-ref |
| P521-SHA512           |     256      | github.com/armfazh/h2c-go-ref |

## Versioning

[SemVer](http://semver.org/) is used for versioning. For the versions available, see the [tags on this repository](https://github.com/bytemare/voprf/tags).

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.