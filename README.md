# (V)OPRF : (Verifiable) Oblivious Pseudorandom Functions

[![VOPRF](https://github.com/bytemare/voprf/actions/workflows/wf-analysis.yaml)](https://github.com/bytemare/voprf/actions/workflows/wf-analysis.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/voprf.svg)](https://pkg.go.dev/github.com/bytemare/voprf)
[![codecov](https://codecov.io/gh/bytemare/voprf/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/voprf)

Package voprf implements [RFC9497](https://datatracker.ietf.org/doc/rfc9497) and provides Oblivious Pseudorandom Functions
(OPRF) over Elliptic Curves, fully supporting the OPRF, VOPRF, and POPRF protocols.

It also offers Threshold-OPRF (TOPRF) for a distributed server setting, as defined in [TOPPSS](https://eprint.iacr.org/2017/363.pdf).
You can use for https://github.com/bytemare/dkg for secure Distributed Key Generation (DKG) to use with this TOPRF.

## Versioning

[SemVer](http://semver.org) is used for versioning. For the versions available, see the [tags on this repository](https://github.com/bytemare/voprf/tags).

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.