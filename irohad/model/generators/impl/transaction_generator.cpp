/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/generators/transaction_generator.hpp"
#include "crypto/keys_manager_impl.hpp"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"
#include "datetime/time.hpp"
#include "model/commands/append_role.hpp"
#include "model/peer.hpp"

namespace iroha {
  namespace model {
    namespace generators {
      const auto kTLSCertificate =
          "-----BEGIN "
          "CERTIFICATE-----\\nMIIDpDCCAoygAwIBAgIULOIAu/"
          "w62xFOFRtPkD88ZuMpGvMwDQYJKoZIhvcNAQEL\\nBQAwWTELMAkGA1UEBhMCQVUxEzA"
          "RBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\\nGEludGVybmV0IFdpZGdpdHMgUHR5"
          "IEx0ZDESMBAGA1UEAwwJbG9jYWxob3N0MB4X\\nDTE5MDYxMDExNTE0NVoXDTE5MDcxM"
          "DExNTE0NVowWTELMAkGA1UEBhMCQVUxEzAR\\nBgNVBAgMClNvbWUtU3RhdGUxITAfBg"
          "NVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5\\nIEx0ZDESMBAGA1UEAwwJbG9jYWxob3N"
          "0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\\nMIIBCgKCAQEAnsM/"
          "pTtpy2hC5evgKBVNGli+/"
          "hbdlFsEelctLrb3zaLlrCUpnLSo\\nqzvJ6v2pubjumTxrlovnuz/"
          "WE9GhvpQsLikjEjIVd6YHzX76vPsdNmM4bn35lyGm\\nCIis3kh36pN93uDlUc/"
          "AkeL2IVzQGS1hznGV2dnI6JNa1VZWzupYVQ1QHI4YfBWs\\n/"
          "P0Xg7k2F9YdK5VW7MH6Zdv4jUoEM2i6joVYAjMUAaLvizw9MayrCMRxaQLnOkLK\\n86"
          "JRQZp8GjXUbwHMVeze3/109aGtVVFwTgKGQukpJE/"
          "bue0J+"
          "ZxDm5glF1MOapCp\\nC0Jb8i61NogiUDTt32uJb0Gmfg7gR5hcBQIDAQABo2QwYjAdBg"
          "NVHQ4EFgQU03y/\\n2UmTHQgpdlyh76+HAIneuCEwHwYDVR0jBBgwFoAU03y/"
          "2UmTHQgpdlyh76+HAIne\\nuCEwDwYDVR0TAQH/BAUwAwEB/zAPBgNVHREECDAGhwR/"
          "AAABMA0GCSqGSIb3DQEB\\nCwUAA4IBAQAMO6uio2ibBYflVgPe0fJjOYvgVCw1GuHFa"
          "EZjWCVht0v5ATzR85VS\\nLSEVc8Zzvb2pT3O1UxvokMuUbeSdOhZZi77llBwGvcHYCy"
          "tv/"
          "C6Yi9zLs1EwDV3j\\nGqwWZdG+"
          "GpfIM2yzsyvvBwdc3AmPyH0ejjiBDyHc5dcgcFlH6L/"
          "N8yaT7J7A9eoK\\nGqVZL1DUvNynEICnT7JFLxpUOE+ejwah7RLyzcSMRWlrN/NX/"
          "GLcsbflXt0dhRfm\\nSwIxR9t/"
          "WTu7iR1TIkDx7tLDt8gPbDbJe732FgLYsTtmV0ShF1Zn28FWMQJg4e0s\\nDUX9rCZ7F"
          "nQAaGqZjuU+mSvfFX7vev7m\\n-----END CERTIFICATE-----\\n";

      iroha::keypair_t *makeOldModel(
          const shared_model::crypto::Keypair &keypair) {
        return new iroha::keypair_t{
            iroha::pubkey_t::from_string(toBinaryString(keypair.publicKey())),
            iroha::privkey_t::from_string(
                toBinaryString(keypair.privateKey()))};
      }

      Transaction TransactionGenerator::generateGenesisTransaction(
          ts64_t timestamp,
          std::vector<std::string> peers_address,
          logger::LoggerPtr keys_manager_logger) {
        Transaction tx;
        tx.created_ts = timestamp;
        tx.creator_account_id = "";
        CommandGenerator command_generator;
        // Add peers
        for (size_t i = 0; i < peers_address.size(); ++i) {
          KeysManagerImpl manager("node" + std::to_string(i),
                                  keys_manager_logger);
          manager.createKeys();
          auto keypair = *std::unique_ptr<iroha::keypair_t>(
              makeOldModel(*manager.loadKeys()));
          tx.commands.push_back(command_generator.generateAddPeer(
              Peer(peers_address[i], keypair.pubkey, kTLSCertificate)));
        }
        // Create admin role
        tx.commands.push_back(
            command_generator.generateCreateAdminRole("admin"));
        // Create user role
        tx.commands.push_back(command_generator.generateCreateUserRole("user"));
        tx.commands.push_back(
            command_generator.generateCreateAssetCreatorRole("money_creator"));
        // Add domain
        tx.commands.push_back(
            command_generator.generateCreateDomain("test", "user"));
        // Create asset
        auto precision = 2;
        tx.commands.push_back(
            command_generator.generateCreateAsset("coin", "test", precision));
        // Create accounts
        KeysManagerImpl manager("admin@test", keys_manager_logger);
        manager.createKeys();
        auto keypair = *std::unique_ptr<iroha::keypair_t>(
            makeOldModel(*manager.loadKeys()));
        tx.commands.push_back(command_generator.generateCreateAccount(
            "admin", "test", keypair.pubkey));
        manager = KeysManagerImpl("test@test", std::move(keys_manager_logger));
        manager.createKeys();
        keypair = *std::unique_ptr<iroha::keypair_t>(
            makeOldModel(*manager.loadKeys()));
        tx.commands.push_back(command_generator.generateCreateAccount(
            "test", "test", keypair.pubkey));

        tx.commands.push_back(
            std::make_shared<AppendRole>("admin@test", "admin"));
        tx.commands.push_back(
            std::make_shared<AppendRole>("admin@test", "money_creator"));
        return tx;
      }

      Transaction TransactionGenerator::generateTransaction(
          ts64_t timestamp,
          std::string creator_account_id,
          std::vector<std::shared_ptr<Command>> commands) {
        Transaction tx;
        tx.created_ts = timestamp;
        tx.creator_account_id = creator_account_id;
        tx.commands = commands;
        return tx;
      }

      Transaction TransactionGenerator::generateTransaction(
          std::string creator_account_id,
          std::vector<std::shared_ptr<Command>> commands) {
        return generateTransaction(
            iroha::time::now(), creator_account_id, commands);
      }

    }  // namespace generators
  }    // namespace model
}  // namespace iroha
