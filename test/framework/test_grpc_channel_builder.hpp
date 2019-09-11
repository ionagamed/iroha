/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TEST_GRPC_CHANNEL_BUILDER_HPP
#define TEST_GRPC_CHANNEL_BUILDER_HPP

#include "network/impl/client_factory.hpp"
#include "network/impl/grpc_channel_builder_params.hpp"

namespace iroha {
  namespace network {

    GrpcClientParams getDefaultTestChannelParams();

    /**
     * Shortcut for @see createClient with default test params
     * @tparam T type for gRPC stub, e.g. proto::Yac
     * @param args @see createClient
     * @return gRPC stub of parametrized type
     */
    template <typename T>
    auto createTestClient(const grpc::string &address) {
      return ClientFactory<T>(std::forward<Types>(args)...,
                              getDefaultTestChannelParams());
    }

    /**
     * Shortcut for @see createSecureClient with default test params
     * @tparam T type for gRPC stub, e.g. proto::Yac
     * @param args @see createSecureClient
     * @return gRPC stub of parametrized type
     */
    template <typename T, typename... Types>
    auto createTestSecureClient(Types &&... args) {
      return createSecureClient<T>(std::forward<Types>(args)...,
                                   getDefaultTestChannelParams());
    }
  }  // namespace network
}  // namespace iroha

#endif /* TEST_GRPC_CHANNEL_BUILDER_HPP */