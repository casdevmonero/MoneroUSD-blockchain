// Copyright (c) 2025, MoneroUSD (USDm) — stablecoin unit tests
// Verifies that USDm (Monero USD) ticker has correct 1:1 peg and mint/burn tx types.

#include "gtest/gtest.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_protocol/enums.h"
#include "offshore/pricing_record.h"

using namespace cryptonote;

namespace
{
  const uint8_t HF_VERSION = 23; // use a recent HF for tests
}

// USDm <-> XUSD conversion rate is fixed 1:1; no oracle required.
TEST(usdm_stablecoin, get_conversion_rate_USDm_to_XUSD_is_one_to_one)
{
  offshore::pricing_record pr;
  uint64_t rate = 0;
  ASSERT_TRUE(get_conversion_rate(pr, "USDm", "XUSD", rate, HF_VERSION));
  EXPECT_EQ(rate, COIN) << "Monero USD (USDm) must convert to XUSD at 1:1";
}

TEST(usdm_stablecoin, get_conversion_rate_XUSD_to_USDm_is_one_to_one)
{
  offshore::pricing_record pr;
  uint64_t rate = 0;
  ASSERT_TRUE(get_conversion_rate(pr, "XUSD", "USDm", rate, HF_VERSION));
  EXPECT_EQ(rate, COIN) << "XUSD must convert to USDm at 1:1";
}

// Mint/burn: USDm -> XUSD = offshore (burn USDm, mint XUSD); XUSD -> USDm = onshore (burn XUSD, mint USDm).
TEST(usdm_stablecoin, get_tx_type_USDm_to_XUSD_is_OFFSHORE)
{
  transaction_type type = transaction_type::UNSET;
  ASSERT_TRUE(get_tx_type("USDm", "XUSD", type));
  EXPECT_EQ(type, transaction_type::OFFSHORE) << "USDm->XUSD must be OFFSHORE (burn USDm, mint XUSD)";
}

TEST(usdm_stablecoin, get_tx_type_XUSD_to_USDm_is_ONSHORE)
{
  transaction_type type = transaction_type::UNSET;
  ASSERT_TRUE(get_tx_type("XUSD", "USDm", type));
  EXPECT_EQ(type, transaction_type::ONSHORE) << "XUSD->USDm must be ONSHORE (burn XUSD, mint USDm)";
}

// Same-asset transfers: no conversion.
TEST(usdm_stablecoin, get_tx_type_USDm_to_USDm_is_TRANSFER)
{
  transaction_type type = transaction_type::UNSET;
  ASSERT_TRUE(get_tx_type("USDm", "USDm", type));
  EXPECT_EQ(type, transaction_type::TRANSFER);
}

TEST(usdm_stablecoin, get_converted_amount_1_to_1_roundtrip)
{
  uint64_t rate = COIN;
  uint64_t one_coin = COIN;
  uint64_t dest = 0;
  ASSERT_TRUE(get_converted_amount(rate, one_coin, dest));
  EXPECT_EQ(dest, one_coin) << "1:1 rate must preserve amount";
}
