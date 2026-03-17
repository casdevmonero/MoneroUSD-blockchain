#pragma once

#include <cstddef>
#include <cstdint>

#ifdef HAVE_FCMP_FFI
extern "C" int fcmp_pp_verify(
  const uint8_t* proof_ptr,
  size_t proof_len,
  const uint8_t* pseudo_outs_ptr,
  size_t pseudo_outs_len,
  const uint8_t* tree_root_ptr,
  size_t tree_root_len,
  uint8_t tree_root_type,
  uint32_t layers,
  const uint8_t* signable_hash_ptr,
  size_t signable_hash_len,
  const uint8_t* key_images_ptr,
  size_t key_images_len
);

extern "C" int fcmp_tree_path(
  const uint8_t* outputs_ptr,
  size_t outputs_len,
  size_t target_index,
  uint8_t** out_ptr,
  size_t* out_len
);

extern "C" int fcmp_hash_c1_leaves(
  const uint8_t* outputs_ptr,
  size_t outputs_len,
  uint8_t* out_ptr,
  size_t out_len
);

extern "C" int fcmp_tree_path_from_c1(
  const uint8_t* outputs_ptr,
  size_t outputs_len,
  const uint8_t* c1_nodes_ptr,
  size_t c1_nodes_len,
  size_t target_group_index,
  uint8_t** out_ptr,
  size_t* out_len
);

extern "C" int fcmp_pp_prove(
  const uint8_t* inputs_ptr,
  size_t inputs_len,
  const uint8_t* pseudo_outs_ptr,
  size_t pseudo_outs_len,
  const uint8_t* signable_hash_ptr,
  size_t signable_hash_len,
  uint8_t** out_proof_ptr,
  size_t* out_proof_len,
  uint8_t* out_tree_root_ptr,
  size_t out_tree_root_len,
  uint8_t* out_tree_root_type,
  uint32_t* out_layers,
  uint8_t* out_key_images_ptr,
  size_t out_key_images_len,
  uint8_t* out_c_tildes_ptr,
  size_t out_c_tildes_len
);

extern "C" void fcmp_free(uint8_t* ptr, size_t len);
#endif
