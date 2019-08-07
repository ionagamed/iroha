/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/tls_keypair.hpp"

#include <fstream>
#include <sstream>

namespace {
  boost::optional<std::string> readFile(const std::string &path) {
    std::ifstream file(path);
    if (!file) {
      return boost::none;
    }

    std::stringstream ss;
    ss << file.rdbuf();
    return ss.str();
  }
}

TLSKeypair::TLSKeypair(const std::string &pem_private_key,
                       const std::string &pem_certificate)
    : pem_private_key(pem_private_key), pem_certificate(pem_certificate) {}

boost::optional<TLSKeypair> TLSKeypairFactory::readFromFiles(
    const std::string &path) {
  auto certificate = readFile(path + ".crt");
  auto private_key = readFile(path + ".key");

  if (!certificate || !private_key) {
    return boost::none;
  }

  return TLSKeypair(*private_key, *certificate);
}