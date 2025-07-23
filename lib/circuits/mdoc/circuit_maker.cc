#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <filesystem>

#include "circuits/mdoc/mdoc_zk.h"

std::string BytesToHexString(const uint8_t* bytes, size_t len) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) {
    ss << std::setw(2) << static_cast<int>(bytes[i]);
  }
  return ss.str();
}

const ZkSpecStruct* FindZkSpecByNumAttributes(int n_attrs) {
  for (size_t i = 0; i < kNumZkSpecs; ++i) {
    if (static_cast<int>(kZkSpecs[i].num_attributes) == n_attrs) {
      return &kZkSpecs[i];
    }
  }
  return nullptr;
}

// Simple command-line parser: --output_dir <dir> --num_attributes <int>
bool ParseCommandLine(int argc, char* argv[], std::string& output_dir, int& num_attributes) {
  output_dir = "circuits";
  num_attributes = 1;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if ((arg == "--output_dir") && i + 1 < argc) {
      output_dir = argv[++i];
    } else if ((arg == "--num_attributes") && i + 1 < argc) {
      num_attributes = std::stoi(argv[++i]);
    } else {
      std::cerr << "Unknown argument: " << arg << std::endl;
      return false;
    }
  }
  return true;
}

int main(int argc, char* argv[]) {
  std::string output_dir;
  int num_attributes;

  if (!ParseCommandLine(argc, argv, output_dir, num_attributes)) {
    std::cerr << "Usage: " << argv[0]
              << " [--output_dir <path>] [--num_attributes <int>]" << std::endl;
    return 1;
  }

  std::cout << "Output directory: " << output_dir << std::endl;
  std::cout << "Requested number of attributes: " << num_attributes << std::endl;

  const ZkSpecStruct* selected_zk_spec = FindZkSpecByNumAttributes(num_attributes);
  if (!selected_zk_spec) {
    std::cerr << "Error: No ZkSpec available for " << num_attributes << " attributes." << std::endl;
    return 1;
  }

  if (!std::filesystem::is_directory(output_dir)) {
    std::cerr << "Error: Output directory does not exist: " << output_dir << std::endl;
    return 1;
  }

  uint8_t* circuit_bytes = nullptr;
  size_t circuit_len = 0;

  std::cout << "Generating circuit..." << std::endl;
  CircuitGenerationErrorCode status = generate_circuit(selected_zk_spec, &circuit_bytes, &circuit_len);
  if (status != CIRCUIT_GENERATION_SUCCESS || !circuit_bytes || circuit_len == 0) {
    std::cerr << "Error generating circuit. Code: " << status << std::endl;
    return 1;
  }

  std::unique_ptr<uint8_t[], decltype(&free)> cleanup(circuit_bytes, &free);

  std::cout << "Circuit generated. Size: " << circuit_len << " bytes." << std::endl;

  uint8_t id_bytes[32];
  if (!circuit_id(id_bytes, circuit_bytes, circuit_len, selected_zk_spec)) {
    std::cerr << "Error computing circuit ID." << std::endl;
    return 1;
  }

  std::string circuit_id_hex = BytesToHexString(id_bytes, 32);
  std::string output_path = (std::filesystem::path(output_dir) / circuit_id_hex).string();

  std::cout << "Writing circuit to: " << output_path << std::endl;

  std::ofstream out_file(output_path, std::ios::binary | std::ios::trunc);
  if (!out_file) {
    std::cerr << "Error opening output file: " << output_path << std::endl;
    return 1;
  }

  out_file.write(reinterpret_cast<const char*>(circuit_bytes), circuit_len);
  if (!out_file) {
    std::cerr << "Error writing to file." << std::endl;
    return 1;
  }

  std::cout << "Circuit successfully written." << std::endl;
  return 0;
}
