/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MAIN_SERVER_RUNNER_HPP
#define MAIN_SERVER_RUNNER_HPP

#include <grpc++/grpc++.h>
#include <grpc++/impl/codegen/service_type.h>
#include "common/result.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class PeerQuery;
  }  // namespace ametsuchi
}  // namespace iroha

/**
 * Class runs Torii server for handling queries and commands.
 */
class ServerRunner {
 public:
  /**
   * Constructor. Initialize a new instance of ServerRunner class.
   * @param address - the address the server will be bind to in URI form
   * @param log to print progress to
   * @param reuse - allow multiple sockets to bind to the same port
   * @param tls_keypair - path to TLS keypair, if TLS is requested.
   * @see iroha::torii::TlsParams
   * @param peer_query - peer query, will be used to verify client connections
   */
  explicit ServerRunner(
      const std::string &address,
      logger::LoggerPtr log,
      bool reuse = true,
      const boost::optional<std::string> &tls_keypair = boost::none,
      const boost::optional<std::shared_ptr<iroha::ametsuchi::PeerQuery>>
              &peer_query = boost::none);

  /**
   * Adds a new grpc service to be run.
   * @param service - service to append.
   * @return reference to this with service appended
   */
  ServerRunner &append(std::shared_ptr<grpc::Service> service);

  /**
   * Initialize the server and run main loop.
   * @return Result with used port number or error message
   */
  iroha::expected::Result<int, std::string> run();

  /**
   * Wait until the server is up.
   */
  void waitForServersReady();

  /**
   * Construct SSL credentials for a secure connection
   * @return Result with server credentials or error message
   */
  iroha::expected::Result<std::shared_ptr<grpc::ServerCredentials>, std::string>
  createSecureCredentials();

  /**
   * Adds a listening port to a ServerBuilder
   * Optionally constructs SSL credentials
   * @param builder builder to which to add the listening port
   * @param selected_port pointer to an int which will contain the selected port
   * @return boost::optional with an error message
   */
  boost::optional<std::string> addListeningPortToBuilder(
      grpc::ServerBuilder &builder, int *selected_port);

  /**
   * Ask grpc server to terminate.
   */
  void shutdown();

  /**
   * Shutdown gRPC server with force on given deadline
   */
  void shutdown(const std::chrono::system_clock::time_point &deadline);

 private:
  logger::LoggerPtr log_;

  std::unique_ptr<grpc::Server> server_instance_;
  std::mutex wait_for_server_;
  std::condition_variable server_instance_cv_;

  std::string server_address_;
  bool reuse_;
  std::vector<std::shared_ptr<grpc::Service>> services_;
  boost::optional<std::string> tls_keypair_;
  boost::optional<
      std::shared_ptr<iroha::ametsuchi::PeerQuery>> peer_query_;
};

#endif  // MAIN_SERVER_RUNNER_HPP
