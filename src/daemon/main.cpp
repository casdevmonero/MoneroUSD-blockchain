// Copyright (c) 2014-2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "common/command_line.h"
#include "common/scoped_message_writer.h"
#include "common/password.h"
#include "common/util.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_basic/miner.h"
#include "crypto/crypto.h"
#include "crypto/chacha.h"
#include "string_tools.h"
#include <fstream>
#include "daemon/command_server.h"
#include "daemon/daemon.h"
#include "daemon/executor.h"
#include "daemonizer/daemonizer.h"
#include "misc_log_ex.h"
#include "net/parse.h"
#include "p2p/net_node.h"
#include "rpc/core_rpc_server.h"
#include "rpc/rpc_args.h"
#include "daemon/command_line_args.h"
#include "version.h"

#ifdef STACK_TRACE
#include "common/stack_trace.h"
#endif // STACK_TRACE

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "daemon"

namespace po = boost::program_options;
namespace bf = boost::filesystem;

uint16_t parse_public_rpc_port(const po::variables_map &vm)
{
  const auto &public_node_arg = daemon_args::arg_public_node;
  const bool public_node = command_line::get_arg(vm, public_node_arg);
  if (!public_node)
  {
    return 0;
  }

  std::string rpc_port_str;
  std::string rpc_bind_address = command_line::get_arg(vm, cryptonote::rpc_args::descriptors().rpc_bind_ip);
  const auto &restricted_rpc_port = cryptonote::core_rpc_server::arg_rpc_restricted_bind_port;
  if (!command_line::is_arg_defaulted(vm, restricted_rpc_port))
  {
    rpc_port_str = command_line::get_arg(vm, restricted_rpc_port);
    rpc_bind_address = command_line::get_arg(vm, cryptonote::rpc_args::descriptors().rpc_restricted_bind_ip);
  }
  else if (command_line::get_arg(vm, cryptonote::core_rpc_server::arg_restricted_rpc))
  {
    rpc_port_str = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_rpc_bind_port);
  }
  else
  {
    throw std::runtime_error("restricted RPC mode is required");
  }

  uint16_t rpc_port;
  if (!string_tools::get_xtype_from_string(rpc_port, rpc_port_str))
  {
    throw std::runtime_error("invalid RPC port " + rpc_port_str);
  }

  const auto address = net::get_network_address(rpc_bind_address, rpc_port);
  if (!address) {
    throw std::runtime_error("failed to parse RPC bind address");
  }
  if (address->get_zone() != epee::net_utils::zone::public_)
  {
    throw std::runtime_error(std::string(zone_to_string(address->get_zone()))
      + " network zone is not supported, please check RPC server bind address");
  }

  if (address->is_loopback() || address->is_local())
  {
    MLOG_RED(el::Level::Warning, "--" << public_node_arg.name 
      << " is enabled, but RPC server " << address->str() 
      << " may be unreachable from outside, please check RPC server bind address");
  }

  return rpc_port;
}

#ifdef WIN32
bool isFat32(const wchar_t* root_path)
{
  std::vector<wchar_t> fs(MAX_PATH + 1);
  if (!::GetVolumeInformationW(root_path, nullptr, 0, nullptr, 0, nullptr, &fs[0], MAX_PATH))
  {
    MERROR("Failed to get '" << root_path << "' filesystem name. Error code: " << ::GetLastError());
    return false;
  }

  return wcscmp(L"FAT32", &fs[0]) == 0;
}
#endif

#if PREMINE_ENABLED
// Print genesis premine keys (deterministic address that receives block 0 reward)
// High-entropy spend key so the 25-word mnemonic is a real phrase (not repeated words).
void print_genesis_premine_keys(const cryptonote::network_type nettype) {
  using namespace cryptonote;
  keypair spend_kp = get_genesis_spend_keypair();
  keypair view_kp = get_view_keypair_from_spend(spend_kp);
  account_public_address addr;
  addr.m_spend_public_key = spend_kp.pub;
  addr.m_view_public_key = view_kp.pub;
  std::cout << "Genesis premine wallet (block 0 reward). Use --generate-from-keys to create wallet." << std::endl;
  std::cout << "Network: " << (nettype == MAINNET ? "mainnet" : nettype == TESTNET ? "testnet" : "stagenet") << std::endl;
  std::cout << std::endl << "Address:" << std::endl;
  std::cout << get_account_address_as_str(nettype, false, addr) << std::endl;
  std::cout << std::endl << "Secret spend key (hex):" << std::endl;
  epee::to_hex::formatted(std::cout, epee::as_byte_span(spend_kp.sec));
  std::cout << std::endl << "Secret view key (hex):" << std::endl;
  epee::to_hex::formatted(std::cout, epee::as_byte_span(view_kp.sec));
  std::cout << std::endl << std::endl;
  std::cout << "Create wallet: Monero USD wallet CLI (USDm-wallet-cli)"
    << (nettype == MAINNET ? "" : nettype == TESTNET ? " --testnet" : " --stagenet")
    << " --generate-from-keys genesis_premine" << std::endl;
  std::cout << "Then paste Address, Spend key, and View key when prompted." << std::endl;
}
#endif

// Helper function to generate genesis transaction
void print_genesis_tx_hex(const cryptonote::network_type nettype) {

  using namespace cryptonote;

  account_base miner_acc1;
  miner_acc1.generate();

  std::cout << "Gennerating miner wallet..." << std::endl;
  std::cout << "Miner account address:" << std::endl;
  std::cout << cryptonote::get_account_address_as_str((network_type)nettype, false, miner_acc1.get_keys().m_account_address);
  std::cout << std::endl << "Miner spend secret key:"  << std::endl;
  epee::to_hex::formatted(std::cout, epee::as_byte_span(miner_acc1.get_keys().m_spend_secret_key));
  std::cout << std::endl << "Miner view secret key:" << std::endl;
  epee::to_hex::formatted(std::cout, epee::as_byte_span(miner_acc1.get_keys().m_view_secret_key));
  std::cout << std::endl << std::endl;

  //Create file with miner keys information
  auto t = std::time(nullptr);
  auto tm = *std::localtime(&t);
  std::stringstream key_fine_name_ss;
  key_fine_name_ss << "./miner01_keys" << std::put_time(&tm, "%Y%m%d%H%M%S") << ".dat";
  std::string key_file_name = key_fine_name_ss.str();
  std::ofstream miner_key_file;
  miner_key_file.open (key_file_name);
  miner_key_file << "Miner account address:" << std::endl;
  miner_key_file << cryptonote::get_account_address_as_str((network_type)nettype, false, miner_acc1.get_keys().m_account_address);
  miner_key_file << std::endl<< "Miner spend secret key:"  << std::endl;
  epee::to_hex::formatted(miner_key_file, epee::as_byte_span(miner_acc1.get_keys().m_spend_secret_key));
  miner_key_file << std::endl << "Miner view secret key:" << std::endl;
  epee::to_hex::formatted(miner_key_file, epee::as_byte_span(miner_acc1.get_keys().m_view_secret_key));
  miner_key_file << std::endl << std::endl;
  miner_key_file.close();


  //Prepare genesis_tx
  cryptonote::transaction tx_genesis;
  std::map<std::string, uint64_t> fee_map, offshore_fee_map, xasset_fee_map;
  cryptonote::construct_miner_tx(0, 0, 0, 10, fee_map, offshore_fee_map, xasset_fee_map, miner_acc1.get_keys().m_account_address, tx_genesis, blobdata(), 999, 1, nettype);
  std::cout << "Object:" << std::endl;
  std::cout << obj_to_json_str(tx_genesis) << std::endl << std::endl;


  std::stringstream ss;
  binary_archive<true> ba(ss);
  ::serialization::serialize(ba, tx_genesis);
  std::string tx_hex = ss.str();
  std::cout << "Insert this line into your coin configuration file: " << std::endl;
  std::cout << "std::string const GENESIS_TX = \"" << string_tools::buff_to_hex_nodelimer(tx_hex) << "\";" << std::endl;

  return;
}

int main(int argc, char const * argv[])
{
  try {

    // TODO parse the debug options like set log level right here at start

    tools::on_startup();

    epee::string_tools::set_module_name_and_folder(argv[0]);

    // Build argument description
    po::options_description all_options("All");
    po::options_description hidden_options("Hidden");
    po::options_description visible_options("Options");
    po::options_description core_settings("Settings");
    po::positional_options_description positional_options;
    {
      // Misc Options

      command_line::add_arg(visible_options, command_line::arg_help);
      command_line::add_arg(visible_options, command_line::arg_version);
      command_line::add_arg(visible_options, daemon_args::arg_os_version);
      command_line::add_arg(visible_options, daemon_args::arg_config_file);
#if PREMINE_ENABLED
      command_line::add_arg(visible_options, daemon_args::arg_print_genesis_keys);
#endif

      // Settings
      command_line::add_arg(core_settings, daemon_args::arg_log_file);
      command_line::add_arg(core_settings, daemon_args::arg_log_level);
      command_line::add_arg(core_settings, daemon_args::arg_max_log_file_size);
      command_line::add_arg(core_settings, daemon_args::arg_max_log_files);
      command_line::add_arg(core_settings, daemon_args::arg_max_concurrency);
      command_line::add_arg(core_settings, daemon_args::arg_proxy);
      command_line::add_arg(core_settings, daemon_args::arg_proxy_allow_dns_leaks);
      command_line::add_arg(core_settings, daemon_args::arg_public_node);
      command_line::add_arg(core_settings, daemon_args::arg_zmq_rpc_bind_ip);
      command_line::add_arg(core_settings, daemon_args::arg_zmq_rpc_bind_port);
      command_line::add_arg(core_settings, daemon_args::arg_zmq_pub);
      command_line::add_arg(core_settings, daemon_args::arg_zmq_rpc_disabled);

      daemonizer::init_options(hidden_options, visible_options);
      daemonize::t_executor::init_options(core_settings);

      // Hidden options
      command_line::add_arg(hidden_options, daemon_args::arg_command);

      visible_options.add(core_settings);
      all_options.add(visible_options);
      all_options.add(hidden_options);

      // Positional
      positional_options.add(daemon_args::arg_command.name, -1); // -1 for unlimited arguments
    }

    // Do command line parsing
    po::variables_map vm;
    bool ok = command_line::handle_error_helper(visible_options, [&]()
    {
      boost::program_options::store(
        boost::program_options::command_line_parser(argc, argv)
          .options(all_options).positional(positional_options).run()
      , vm
      );

      return true;
    });
    if (!ok) return 1;

    if (command_line::get_arg(vm, command_line::arg_help))
    {
      std::cout << "Monero USD '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL << ENDL;
      std::cout << "Usage: " + std::string{argv[0]} + " [options|settings] [daemon_command...]" << std::endl << std::endl;
      std::cout << visible_options << std::endl;
      return 0;
    }

    // Monero Version
    if (command_line::get_arg(vm, command_line::arg_version))
    {
      std::cout << "Monero USD '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL;
      return 0;
    }

    // OS
    if (command_line::get_arg(vm, daemon_args::arg_os_version))
    {
      std::cout << "OS: " << tools::get_os_version_string() << ENDL;
      return 0;
    }

    std::string config = command_line::get_arg(vm, daemon_args::arg_config_file);
    boost::filesystem::path config_path(config);
    boost::system::error_code ec;
    if (bf::exists(config_path, ec))
    {
      try
      {
        po::store(po::parse_config_file<char>(config_path.string<std::string>().c_str(), core_settings), vm);
      }
      catch (const std::exception &e)
      {
        // log system isn't initialized yet
        std::cerr << "Error parsing config file: " << e.what() << std::endl;
        throw;
      }
    }
    else if (!command_line::is_arg_defaulted(vm, daemon_args::arg_config_file))
    {
      std::cerr << "Can't find config file " << config << std::endl;
      return 1;
    }

    const bool testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
    const bool stagenet = command_line::get_arg(vm, cryptonote::arg_stagenet_on);
    const bool regtest = command_line::get_arg(vm, cryptonote::arg_regtest_on);
    if (testnet + stagenet + regtest > 1)
    {
      std::cerr << "Can't specify more than one of --tesnet and --stagenet and --regtest" << ENDL;
      return 1;
    }

#if PREMINE_ENABLED
    if (command_line::get_arg(vm, daemon_args::arg_print_genesis_keys))
    {
      cryptonote::network_type nettype = cryptonote::MAINNET;
      if (testnet) nettype = cryptonote::TESTNET;
      else if (stagenet) nettype = cryptonote::STAGENET;
      print_genesis_premine_keys(nettype);
      return 0;
    }
#endif

#if defined(ENABLE_XMR_MINT) && (ENABLE_XMR_MINT != 0)
    // Mint authority key management — encrypted at rest with ChaCha20.
    // Key lifecycle:
    //   1. First run: generates keypair, encrypts secret key with passphrase, saves to .enc file
    //   2. Subsequent runs: loads encrypted file, decrypts with passphrase, sets env var
    //   3. Passphrase source: MINT_KEY_PASSPHRASE env var (required for non-interactive/systemd)
    //   4. Secret key is ONLY held in process memory — never written to disk in plaintext
    {
      const char* existing_sk = std::getenv("MINT_AUTHORITY_SECRET_KEY");
      if (!existing_sk || std::strlen(existing_sk) != 64) {
        boost::filesystem::path data_dir_tmp = boost::filesystem::absolute(
            command_line::get_arg(vm, cryptonote::arg_data_dir));
        boost::filesystem::path enc_keyfile = data_dir_tmp / "mint_authority.key.enc";
        boost::filesystem::path legacy_keyfile = data_dir_tmp / "mint_authority.key";

        // Get passphrase from environment (for systemd/non-interactive) or use default
        std::string passphrase;
        const char* pp_env = std::getenv("MINT_KEY_PASSPHRASE");
        if (pp_env && std::strlen(pp_env) > 0) {
          passphrase = std::string(pp_env);
        } else {
          // Use a machine-specific default derived from data dir path
          // (Better than plaintext, but operators should set MINT_KEY_PASSPHRASE for production)
          passphrase = "monerousd-mint-" + data_dir_tmp.string();
          std::cerr << "Warning: MINT_KEY_PASSPHRASE not set. Using default passphrase." << std::endl;
          std::cerr << "  For production, set MINT_KEY_PASSPHRASE env var to a strong passphrase." << std::endl;
        }

        // Derive ChaCha20 encryption key from passphrase (same KDF as wallet .keys files)
        crypto::chacha_key enc_key;
        crypto::generate_chacha_key(passphrase, enc_key, 1);

        if (boost::filesystem::exists(enc_keyfile)) {
          // Load and decrypt existing encrypted key
          std::ifstream ifs(enc_keyfile.string(), std::ios::binary);
          std::string enc_data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
          ifs.close();
          // Format: [8-byte IV][64-byte encrypted hex string]
          if (enc_data.size() == sizeof(crypto::chacha_iv) + 64) {
            crypto::chacha_iv iv;
            memcpy(&iv, enc_data.data(), sizeof(iv));
            std::string sk_hex(64, '\0');
            crypto::chacha20(enc_data.data() + sizeof(iv), 64, enc_key, iv, &sk_hex[0]);
            // Verify decryption produced a valid key by deriving pubkey
            crypto::secret_key sk;
            if (epee::string_tools::hex_to_pod(sk_hex, sk)) {
              crypto::public_key pk;
              if (crypto::secret_key_to_public_key(sk, pk)) {
                setenv("MINT_AUTHORITY_SECRET_KEY", sk_hex.c_str(), 1);
                std::cerr << "Mint authority loaded from " << enc_keyfile << " (encrypted)" << std::endl;
                std::cerr << "  Public key: " << epee::string_tools::pod_to_hex(pk) << std::endl;
              } else {
                std::cerr << "ERROR: Failed to derive pubkey — wrong passphrase?" << std::endl;
                std::cerr << "  Set MINT_KEY_PASSPHRASE to the correct passphrase." << std::endl;
              }
            } else {
              std::cerr << "ERROR: Failed to decrypt mint authority key. Wrong passphrase?" << std::endl;
              std::cerr << "  Set MINT_KEY_PASSPHRASE to the correct passphrase." << std::endl;
            }
            memset(&sk_hex[0], 0, sk_hex.size());
          } else {
            std::cerr << "ERROR: Corrupt encrypted key file: " << enc_keyfile << std::endl;
          }
        } else if (boost::filesystem::exists(legacy_keyfile)) {
          // Migrate legacy plaintext key to encrypted format
          std::ifstream ifs(legacy_keyfile.string());
          std::string sk_hex;
          std::getline(ifs, sk_hex);
          ifs.close();
          if (sk_hex.size() == 64) {
            crypto::secret_key sk;
            crypto::public_key pk;
            epee::string_tools::hex_to_pod(sk_hex, sk);
            crypto::secret_key_to_public_key(sk, pk);
            // Encrypt the hex string with ChaCha20
            crypto::chacha_iv iv;
            crypto::rand(sizeof(iv), reinterpret_cast<uint8_t*>(&iv));
            std::string encrypted(64, '\0');
            crypto::chacha20(sk_hex.data(), 64, enc_key, iv, &encrypted[0]);
            {
              std::ofstream ofs(enc_keyfile.string(), std::ios::binary);
              ofs.write(reinterpret_cast<const char*>(&iv), sizeof(iv));
              ofs.write(encrypted.data(), 64);
            }
            boost::filesystem::permissions(enc_keyfile, boost::filesystem::owner_read);
            // Remove the plaintext key file
            boost::filesystem::remove(legacy_keyfile);
            setenv("MINT_AUTHORITY_SECRET_KEY", sk_hex.c_str(), 1);
            std::cerr << "Migrated mint authority key to encrypted format:" << std::endl;
            std::cerr << "  Encrypted key: " << enc_keyfile << " (chmod 400)" << std::endl;
            std::cerr << "  Plaintext key removed: " << legacy_keyfile << std::endl;
            std::cerr << "  Public key: " << epee::string_tools::pod_to_hex(pk) << std::endl;
            memset(&sk_hex[0], 0, sk_hex.size());
            memset(&encrypted[0], 0, encrypted.size());
          }
        } else {
          // Generate new keypair and save encrypted
          crypto::secret_key sk;
          crypto::public_key pk;
          crypto::generate_keys(pk, sk);
          std::string sk_hex = epee::string_tools::pod_to_hex(sk);
          std::string pk_hex = epee::string_tools::pod_to_hex(pk);
          // Encrypt the hex string with ChaCha20
          crypto::chacha_iv iv;
          crypto::rand(sizeof(iv), reinterpret_cast<uint8_t*>(&iv));
          std::string encrypted(64, '\0');
          crypto::chacha20(sk_hex.data(), 64, enc_key, iv, &encrypted[0]);
          // Write encrypted key file
          {
            std::ofstream ofs(enc_keyfile.string(), std::ios::binary);
            ofs.write(reinterpret_cast<const char*>(&iv), sizeof(iv));
            ofs.write(encrypted.data(), 64);
          }
          boost::filesystem::permissions(enc_keyfile, boost::filesystem::owner_read);
          setenv("MINT_AUTHORITY_SECRET_KEY", sk_hex.c_str(), 1);
          std::cerr << "Generated new mint authority keypair (encrypted):" << std::endl;
          std::cerr << "  Encrypted key saved to: " << enc_keyfile << " (chmod 400)" << std::endl;
          std::cerr << "  Public key: " << pk_hex << std::endl;
          std::cerr << "  *** UPDATE cryptonote_config.h MINT_AUTHORITY_PUBKEY_HEX to: " << pk_hex << " ***" << std::endl;
          // Scrub secrets from memory
          memset(&sk_hex[0], 0, sk_hex.size());
          memset(&encrypted[0], 0, encrypted.size());
        }
        // Scrub encryption key and passphrase from memory
        memset(&unwrap(unwrap(enc_key)), 0, sizeof(enc_key));
        memset(&passphrase[0], 0, passphrase.size());
      } else {
        crypto::secret_key sk;
        crypto::public_key pk;
        epee::string_tools::hex_to_pod(std::string(existing_sk), sk);
        crypto::secret_key_to_public_key(sk, pk);
        std::cerr << "Mint authority from env: pubkey=" << epee::string_tools::pod_to_hex(pk) << std::endl;
      }
    }
#endif

    // data_dir
    //   default: e.g. ~/.bitmonero/ or ~/.bitmonero/testnet
    //   if data-dir argument given:
    //     absolute path
    //     relative path: relative to cwd

    // Create data dir if it doesn't exist
    boost::filesystem::path data_dir = boost::filesystem::absolute(
        command_line::get_arg(vm, cryptonote::arg_data_dir));

#ifdef WIN32
    if (isFat32(data_dir.root_path().c_str()))
    {
      MERROR("Data directory resides on FAT32 volume that has 4GiB file size limit, blockchain might get corrupted.");
    }
#endif

    // FIXME: not sure on windows implementation default, needs further review
    //bf::path relative_path_base = daemonizer::get_relative_path_base(vm);
    bf::path relative_path_base = data_dir;

    po::notify(vm);

    // log_file_path
    //   default: <data_dir>/<CRYPTONOTE_NAME>.log
    //   if log-file argument given:
    //     absolute path
    //     relative path: relative to data_dir
    bf::path log_file_path {data_dir / std::string(CRYPTONOTE_NAME ".log")};
    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_log_file))
      log_file_path = command_line::get_arg(vm, daemon_args::arg_log_file);
    if (!log_file_path.has_parent_path())
      log_file_path = bf::absolute(log_file_path, relative_path_base);
    mlog_configure(log_file_path.string(), true, command_line::get_arg(vm, daemon_args::arg_max_log_file_size), command_line::get_arg(vm, daemon_args::arg_max_log_files));

    // Set log level
    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_log_level))
    {
      mlog_set_log(command_line::get_arg(vm, daemon_args::arg_log_level).c_str());
    }

    // after logs initialized
    tools::create_directories_if_necessary(data_dir.string());

#ifdef STACK_TRACE
    tools::set_stack_trace_log(log_file_path.filename().string());
#endif // STACK_TRACE

    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_max_concurrency))
      tools::set_max_concurrency(command_line::get_arg(vm, daemon_args::arg_max_concurrency));

    // logging is now set up
    MGINFO("Monero USD '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")");

    // If there are positional options, we're running a daemon command
    {
      auto command = command_line::get_arg(vm, daemon_args::arg_command);

      if (command.size())
      {
        const cryptonote::rpc_args::descriptors arg{};
        auto rpc_ip_str = command_line::get_arg(vm, arg.rpc_bind_ip);
        auto rpc_port_str = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_rpc_bind_port);

        uint32_t rpc_ip;
        uint16_t rpc_port;
        if (!epee::string_tools::get_ip_int32_from_string(rpc_ip, rpc_ip_str))
        {
          std::cerr << "Invalid IP: " << rpc_ip_str << std::endl;
          return 1;
        }
        if (!epee::string_tools::get_xtype_from_string(rpc_port, rpc_port_str))
        {
          std::cerr << "Invalid port: " << rpc_port_str << std::endl;
          return 1;
        }

        const char *env_rpc_login = nullptr;
        const bool has_rpc_arg = command_line::has_arg(vm, arg.rpc_login);
        const bool use_rpc_env = !has_rpc_arg && (env_rpc_login = getenv("RPC_LOGIN")) != nullptr && strlen(env_rpc_login) > 0;
        boost::optional<tools::login> login{};
        if (has_rpc_arg || use_rpc_env)
        {
          login = tools::login::parse(
            has_rpc_arg ? command_line::get_arg(vm, arg.rpc_login) : std::string(env_rpc_login), false, [](bool verify) {
              PAUSE_READLINE();
              return tools::password_container::prompt(verify, "Daemon client password");
            }
          );
          if (!login)
          {
            std::cerr << "Failed to obtain password" << std::endl;
            return 1;
          }
        }

        auto ssl_options = cryptonote::rpc_args::process_ssl(vm, true);
        if (!ssl_options)
          return 1;

        daemonize::t_command_server rpc_commands{rpc_ip, rpc_port, std::move(login), std::move(*ssl_options)};
        if (rpc_commands.process_command_vec(command))
        {
          return 0;
        }
        else
        {
          PAUSE_READLINE();
          std::cerr << "Unknown command: " << command.front() << std::endl;
          return 1;
        }
      }
    }

    MINFO("Moving from main() into the daemonize now.");

    return daemonizer::daemonize(argc, argv, daemonize::t_executor{parse_public_rpc_port(vm)}, vm) ? 0 : 1;
  }
  catch (std::exception const & ex)
  {
    LOG_ERROR("Exception in main! " << ex.what());
  }
  catch (...)
  {
    LOG_ERROR("Exception in main!");
  }
  return 1;
}
