/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CHANNEL_POOL_HPP
#define IROHA_CHANNEL_POOL_HPP

#include <string>
#include <unordered_map>

#include <grpc++/grpc++.h>

#include "ametsuchi/peer_query.hpp"

namespace iroha {
  namespace network {
    class ChannelFactory;

    class ChannelPool {
     public:
      /**
       * Constructor with TLS, fetching certificates from peers
       * @param peer_query peer query to use for certificate search
       * @param keypair_path optional path to a pair of PEM-encoded key and
       *        certificate for client authentication
       */
      explicit ChannelPool(std::unique_ptr<ChannelFactory> channel_factory);

      /**
       * Get or create a grpc::Channel (from a pool of channels)
       * @param address address to connect to (ip:port)
       * @param root_certificate_path - (optionally) override the certificate
       *        for TLS
       * @return std::shared_ptr<grpc::Channel> to that address
       */
      std::shared_ptr<grpc::Channel> getChannel(
          const std::string &service_full_name, const std::string &address);

     private:
      std::unique_ptr<ChannelFactory> channel_factory_;
      std::unordered_map<std::string, std::shared_ptr<grpc::Channel>> channels_;
    };

  }  // namespace network
}  // namespace iroha

#endif