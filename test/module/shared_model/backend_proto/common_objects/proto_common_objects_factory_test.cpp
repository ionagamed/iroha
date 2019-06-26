/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "backend/protobuf/common_objects/proto_common_objects_factory.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "framework/result_fixture.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "validators/field_validator.hpp"

using namespace shared_model;
using namespace framework::expected;

class ProtoFixture : public ::testing::Test {
 public:
  ProtoFixture() : factory(iroha::test::kTestsValidatorsConfig) {}

  proto::ProtoCommonObjectsFactory<validation::FieldValidator> factory;
};

class PeerTest : public ProtoFixture {
 public:
  std::string valid_address = "127.0.0.1:8080";
  crypto::PublicKey valid_pubkey =
      crypto::DefaultCryptoAlgorithmType::generateKeypair().publicKey();
  std::string invalid_address = "127.0.0.1";
  std::string tls_certificate =
      "-----BEGIN "
      "CERTIFICATE-----\\nMIIDpDCCAoygAwIBAgIULOIAu/"
      "w62xFOFRtPkD88ZuMpGvMwDQYJKoZIhvcNAQEL\\nBQAwWTELMAkGA1UEBhMCQVUxEzARBgN"
      "VBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDES"
      "MBAGA1UEAwwJbG9jYWxob3N0MB4X\\nDTE5MDYxMDExNTE0NVoXDTE5MDcxMDExNTE0NVowW"
      "TELMAkGA1UEBhMCQVUxEzAR\\nBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybm"
      "V0IFdpZGdpdHMgUHR5\\nIEx0ZDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0"
      "BAQEFAAOCAQ8A\\nMIIBCgKCAQEAnsM/pTtpy2hC5evgKBVNGli+/"
      "hbdlFsEelctLrb3zaLlrCUpnLSo\\nqzvJ6v2pubjumTxrlovnuz/"
      "WE9GhvpQsLikjEjIVd6YHzX76vPsdNmM4bn35lyGm\\nCIis3kh36pN93uDlUc/"
      "AkeL2IVzQGS1hznGV2dnI6JNa1VZWzupYVQ1QHI4YfBWs\\n/"
      "P0Xg7k2F9YdK5VW7MH6Zdv4jUoEM2i6joVYAjMUAaLvizw9MayrCMRxaQLnOkLK\\n86JRQZ"
      "p8GjXUbwHMVeze3/109aGtVVFwTgKGQukpJE/"
      "bue0J+"
      "ZxDm5glF1MOapCp\\nC0Jb8i61NogiUDTt32uJb0Gmfg7gR5hcBQIDAQABo2QwYjAdBgNVHQ"
      "4EFgQU03y/\\n2UmTHQgpdlyh76+HAIneuCEwHwYDVR0jBBgwFoAU03y/"
      "2UmTHQgpdlyh76+HAIne\\nuCEwDwYDVR0TAQH/BAUwAwEB/zAPBgNVHREECDAGhwR/"
      "AAABMA0GCSqGSIb3DQEB\\nCwUAA4IBAQAMO6uio2ibBYflVgPe0fJjOYvgVCw1GuHFaEZjW"
      "CVht0v5ATzR85VS\\nLSEVc8Zzvb2pT3O1UxvokMuUbeSdOhZZi77llBwGvcHYCytv/"
      "C6Yi9zLs1EwDV3j\\nGqwWZdG+GpfIM2yzsyvvBwdc3AmPyH0ejjiBDyHc5dcgcFlH6L/"
      "N8yaT7J7A9eoK\\nGqVZL1DUvNynEICnT7JFLxpUOE+ejwah7RLyzcSMRWlrN/NX/"
      "GLcsbflXt0dhRfm\\nSwIxR9t/"
      "WTu7iR1TIkDx7tLDt8gPbDbJe732FgLYsTtmV0ShF1Zn28FWMQJg4e0s\\nDUX9rCZ7FnQAa"
      "GqZjuU+mSvfFX7vev7m\\n-----END CERTIFICATE-----\\n";
};

/**
 * @given valid data for peer
 * @when peer is created via factory
 * @then peer is successfully initialized
 */
TEST_F(PeerTest, ValidPeerInitialization) {
  auto peer = factory.createPeer(valid_address, valid_pubkey, tls_certificate);

  peer.match(
      [&](const auto &v) {
        ASSERT_EQ(v.value->address(), valid_address);
        ASSERT_EQ(v.value->pubkey().hex(), valid_pubkey.hex());
      },
      [](const auto &e) { FAIL() << e.error; });
}

/**
 * @given invalid data for peer
 * @when peer is created via factory
 * @then peer is not initialized correctly
 */
TEST_F(PeerTest, InvalidPeerInitialization) {
  auto peer =
      factory.createPeer(invalid_address, valid_pubkey, tls_certificate);

  peer.match([](const auto &v) { FAIL() << "Expected error case"; },
             [](const auto &e) { SUCCEED(); });
}

class AccountTest : public ProtoFixture {
 public:
  interface::types::AccountIdType valid_account_id = "hello@world";
  interface::types::DomainIdType valid_domain_id = "bit.connect";
  interface::types::QuorumType valid_quorum = 1;
  interface::types::JsonType valid_json = R"({"name": "json" })";

  interface::types::AccountIdType invalid_account_id = "hello123";
};

/**
 * @given valid data for account
 * @when account is created via factory
 * @then peer is successfully initialized
 */
TEST_F(AccountTest, ValidAccountInitialization) {
  auto account = factory.createAccount(
      valid_account_id, valid_domain_id, valid_quorum, valid_json);

  account.match(
      [&](const auto &v) {
        ASSERT_EQ(v.value->accountId(), valid_account_id);
        ASSERT_EQ(v.value->domainId(), valid_domain_id);
        ASSERT_EQ(v.value->quorum(), valid_quorum);
        ASSERT_EQ(v.value->jsonData(), valid_json);
      },
      [](const auto &e) { FAIL() << e.error; });
}

/**
 * @given invalid data for account
 * @when account is created via factory
 * @then account is not initialized correctly
 */
TEST_F(AccountTest, InvalidAccountInitialization) {
  auto account = factory.createAccount(
      invalid_account_id, valid_domain_id, valid_quorum, valid_json);

  account.match([](const auto &v) { FAIL() << "Expected error case"; },
                [](const auto &e) { SUCCEED(); });
}

class AccountAssetTest : public ProtoFixture {
 public:
  interface::types::AccountIdType valid_account_id = "hello@world";
  interface::types::AssetIdType valid_asset_id = "bit#connect";
  interface::Amount valid_amount = interface::Amount("10.00");

  interface::types::AccountIdType invalid_account_id = "hello123";
};

/**
 * @given valid data for account asset
 * @when account asset is created via factory
 * @then account asset is successfully initialized
 */
TEST_F(AccountAssetTest, ValidAccountAssetInitialization) {
  auto account_asset = factory.createAccountAsset(
      valid_account_id, valid_asset_id, valid_amount);

  account_asset.match(
      [&](const auto &v) {
        ASSERT_EQ(v.value->accountId(), valid_account_id);
        ASSERT_EQ(v.value->assetId(), valid_asset_id);
        ASSERT_EQ(v.value->balance(), valid_amount);
      },
      [](const auto &e) { FAIL() << e.error; });
}

/**
 * @given invalid data for account asset
 * @when account asset is created via factory
 * @then account asset is not initialized correctly
 */
TEST_F(AccountAssetTest, InvalidAccountAssetInitialization) {
  auto account_asset = factory.createAccountAsset(
      invalid_account_id, valid_asset_id, valid_amount);

  account_asset.match([](const auto &v) { FAIL() << "Expected error case"; },
                      [](const auto &e) { SUCCEED(); });
}

class AssetTest : public ProtoFixture {
 public:
  interface::types::AssetIdType valid_asset_id = "bit#connect";
  interface::types::DomainIdType valid_domain_id = "iroha.com";
  interface::types::PrecisionType valid_precision = 2;

  interface::types::AssetIdType invalid_asset_id = "bit";
};

/**
 * @given valid data for asset
 * @when asset is created via factory
 * @then asset is successfully initialized
 */
TEST_F(AssetTest, ValidAssetInitialization) {
  auto asset =
      factory.createAsset(valid_asset_id, valid_domain_id, valid_precision);

  asset.match(
      [&](const auto &v) {
        ASSERT_EQ(v.value->assetId(), valid_asset_id);
        ASSERT_EQ(v.value->domainId(), valid_domain_id);
        ASSERT_EQ(v.value->precision(), valid_precision);
      },
      [](const auto &e) { FAIL() << e.error; });
}

/**
 * @given invalid data for asset
 * @when asset is created via factory
 * @then asset is not initialized correctly
 */
TEST_F(AssetTest, InvalidAssetInitialization) {
  auto asset =
      factory.createAsset(invalid_asset_id, valid_domain_id, valid_precision);

  asset.match([](const auto &v) { FAIL() << "Expected error case"; },
              [](const auto &e) { SUCCEED(); });
}

class DomainTest : public ProtoFixture {
 public:
  interface::types::DomainIdType valid_domain_id = "iroha.com";
  interface::types::RoleIdType valid_role_id = "admin";

  interface::types::DomainIdType invalid_domain_id = "123irohacom";
};

/**
 * @given valid data for domain
 * @when domain is created via factory
 * @then domain is successfully initialized
 */
TEST_F(DomainTest, ValidDomainInitialization) {
  auto domain = factory.createDomain(valid_domain_id, valid_role_id);

  domain.match(
      [&](const auto &v) {
        ASSERT_EQ(v.value->domainId(), valid_domain_id);
        ASSERT_EQ(v.value->defaultRole(), valid_role_id);
      },
      [](const auto &e) { FAIL() << e.error; });
}

/**
 * @given invalid data for domain
 * @when domain is created via factory
 * @then domain is not initialized correctly
 */
TEST_F(DomainTest, InvalidDomainInitialization) {
  auto domain = factory.createDomain(invalid_domain_id, valid_role_id);

  domain.match([](const auto &v) { FAIL() << "Expected error case"; },
               [](const auto &e) { SUCCEED(); });
}

class SignatureTest : public ProtoFixture {
 public:
  crypto::PublicKey valid_pubkey =
      crypto::DefaultCryptoAlgorithmType::generateKeypair().publicKey();
  crypto::Signed valid_data{"hello"};
  crypto::PublicKey invalid_pubkey{"1234"};
};

/**
 * @given valid data for signature
 * @when signature is created via factory
 * @then signature is successfully initialized
 */
TEST_F(SignatureTest, ValidSignatureInitialization) {
  auto signature = factory.createSignature(valid_pubkey, valid_data);

  signature.match(
      [&](const auto &v) {
        ASSERT_EQ(v.value->publicKey().hex(), valid_pubkey.hex());
        ASSERT_EQ(v.value->signedData().hex(), valid_data.hex());
      },
      [](const auto &e) { FAIL() << e.error; });
}

/**
 * @given invalid data for signature
 * @when signature is created via factory
 * @then signature is not initialized correctly
 */
TEST_F(SignatureTest, InvalidSignatureInitialization) {
  auto signature = factory.createSignature(invalid_pubkey, valid_data);

  signature.match([](const auto &v) { FAIL() << "Expected error case"; },
                  [](const auto &e) { SUCCEED(); });
}
