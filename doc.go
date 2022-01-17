// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package voprf provides abstracted access to Oblivious Pseudorandom Functions (OPRF)
// and VOPRF Oblivious Pseudorandom Functions (VOPRF) using Elliptic Curves (EC(V)OPRF).
//
// This work in progress implements https://tools.ietf.org/html/draft-irtf-cfrg-voprf
//
// Integrations can use either base or verifiable mode with additive or multiplicative operations.
package voprf
