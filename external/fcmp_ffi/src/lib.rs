#![allow(non_snake_case)]

use std::io;
use std::io::Write;

use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, OsRng};

use ciphersuite::Ciphersuite;
use dalek_ff_group::Ed25519;
use helioselene::{Selene, Helios};

use generalized_bulletproofs::Generators as GbGenerators;
use multiexp::BatchVerifier;

use ciphersuite::group::ff::{PrimeField, Field};
use ciphersuite::group::{Group, GroupEncoding};
use ec_divisors::DivisorCurve;
use fcmps::{TreeRoot, LAYER_ONE_LEN, LAYER_TWO_LEN};
use monero_fcmp_plus_plus::{
  Curves,
  FcmpPlusPlus,
  Output,
  FCMP_PARAMS,
  SELENE_FCMP_GENERATORS,
  HELIOS_FCMP_GENERATORS,
};
use monero_generators::{T, FCMP_PLUS_PLUS_U, FCMP_PLUS_PLUS_V, SELENE_HASH_INIT, HELIOS_HASH_INIT};
use fcmps::{Path, Branches, OutputBlinds, OBlind, IBlind, IBlindBlind, CBlind, BranchBlind, Fcmp};
use ec_divisors::ScalarDecomposition;
use dalek_ff_group::{Scalar, EdwardsPoint};
use monero_fcmp_plus_plus::sal::{RerandomizedOutput, OpenedInputTuple, SpendAuthAndLinkability};
use multiexp::multiexp_vartime;

fn read_point<C: Ciphersuite>(bytes: &[u8]) -> io::Result<C::G> {
  let mut reader = bytes;
  C::read_G(&mut reader)
}

fn read_output_tuple(bytes: &[u8]) -> io::Result<Output> {
  if bytes.len() != 96 {
    return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid output tuple length"));
  }
  let O = read_point::<Ed25519>(&bytes[0..32])?;
  let I = read_point::<Ed25519>(&bytes[32..64])?;
  let C = read_point::<Ed25519>(&bytes[64..96])?;
  Output::new(O, I, C).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid output tuple"))
}

fn c1_hash_leaves(outputs: &[Output]) -> <Selene as Ciphersuite>::G {
  let mut items = Vec::with_capacity(LAYER_ONE_LEN * 6);
  for (i, output) in outputs.iter().enumerate() {
    let (o_x, o_y) = <Ed25519 as Ciphersuite>::G::to_xy(output.O()).unwrap();
    let (i_x, i_y) = <Ed25519 as Ciphersuite>::G::to_xy(output.I()).unwrap();
    let (c_x, c_y) = <Ed25519 as Ciphersuite>::G::to_xy(output.C()).unwrap();
    for (scalar, point) in [o_x, o_y, i_x, i_y, c_x, c_y]
      .into_iter()
      .zip(SELENE_FCMP_GENERATORS.generators.g_bold_slice().iter().copied().skip(i * 6))
    {
      items.push((scalar, point));
    }
  }
  let mut padding = (LAYER_ONE_LEN - outputs.len()) * 6;
  let mut idx = outputs.len() * 6;
  while padding > 0 {
    items.push((<Selene as Ciphersuite>::F::ZERO, *SELENE_FCMP_GENERATORS.generators.g_bold_slice().get(idx).unwrap()));
    idx += 1;
    padding -= 1;
  }
  *SELENE_HASH_INIT + multiexp_vartime(&items)
}

fn c2_hash_nodes(nodes: &[<Selene as Ciphersuite>::G]) -> <Helios as Ciphersuite>::G {
  let mut items = Vec::with_capacity(LAYER_TWO_LEN);
  let mut idx = 0;
  for node in nodes.iter() {
    let (x, _) = <Selene as Ciphersuite>::G::to_xy(*node).unwrap();
    let x2 = <Helios as Ciphersuite>::F::from_repr(x.to_repr()).unwrap();
    items.push((x2, *HELIOS_FCMP_GENERATORS.generators.g_bold_slice().get(idx).unwrap()));
    idx += 1;
  }
  while idx < LAYER_TWO_LEN {
    items.push((<Helios as Ciphersuite>::F::ZERO, *HELIOS_FCMP_GENERATORS.generators.g_bold_slice().get(idx).unwrap()));
    idx += 1;
  }
  *HELIOS_HASH_INIT + multiexp_vartime(&items)
}

fn c1_hash_nodes(nodes: &[<Helios as Ciphersuite>::G]) -> <Selene as Ciphersuite>::G {
  let mut items = Vec::with_capacity(LAYER_ONE_LEN);
  let mut idx = 0;
  for node in nodes.iter() {
    let (x, _) = <Helios as Ciphersuite>::G::to_xy(*node).unwrap();
    let x1 = <Selene as Ciphersuite>::F::from_repr(x.to_repr()).unwrap();
    items.push((x1, *SELENE_FCMP_GENERATORS.generators.g_bold_slice().get(idx).unwrap()));
    idx += 1;
  }
  while idx < LAYER_ONE_LEN {
    items.push((<Selene as Ciphersuite>::F::ZERO, *SELENE_FCMP_GENERATORS.generators.g_bold_slice().get(idx).unwrap()));
    idx += 1;
  }
  *SELENE_HASH_INIT + multiexp_vartime(&items)
}

fn c2_hash_scalars(scalars: &[<Helios as Ciphersuite>::F]) -> <Helios as Ciphersuite>::G {
  let mut items = Vec::with_capacity(LAYER_TWO_LEN);
  let mut idx = 0;
  for scalar in scalars.iter() {
    items.push((*scalar, *HELIOS_FCMP_GENERATORS.generators.g_bold_slice().get(idx).unwrap()));
    idx += 1;
  }
  while idx < LAYER_TWO_LEN {
    items.push((<Helios as Ciphersuite>::F::ZERO, *HELIOS_FCMP_GENERATORS.generators.g_bold_slice().get(idx).unwrap()));
    idx += 1;
  }
  *HELIOS_HASH_INIT + multiexp_vartime(&items)
}

fn c1_hash_scalars(scalars: &[<Selene as Ciphersuite>::F]) -> <Selene as Ciphersuite>::G {
  let mut items = Vec::with_capacity(LAYER_ONE_LEN);
  let mut idx = 0;
  for scalar in scalars.iter() {
    items.push((*scalar, *SELENE_FCMP_GENERATORS.generators.g_bold_slice().get(idx).unwrap()));
    idx += 1;
  }
  while idx < LAYER_ONE_LEN {
    items.push((<Selene as Ciphersuite>::F::ZERO, *SELENE_FCMP_GENERATORS.generators.g_bold_slice().get(idx).unwrap()));
    idx += 1;
  }
  *SELENE_HASH_INIT + multiexp_vartime(&items)
}

fn debug_check_path(
  leaves: &[Output],
  curve_2_layers: &[Vec<<Helios as Ciphersuite>::F>],
  curve_1_layers: &[Vec<<Selene as Ciphersuite>::F>],
  root_type: u8,
  root_bytes: &[u8; 32],
) {
  let mut current_c1 = c1_hash_leaves(leaves);
  let mut c2_idx = 0usize;
  let mut c1_idx = 0usize;
  let mut computed_root_type = 1u8;
  let mut computed_root_bytes = current_c1.to_bytes();

  if curve_2_layers.is_empty() && curve_1_layers.is_empty() {
    computed_root_type = 1;
    computed_root_bytes = current_c1.to_bytes();
  } else {
    loop {
      if c2_idx < curve_2_layers.len() {
        let (x, _) = <Selene as Ciphersuite>::G::to_xy(current_c1).unwrap();
        let c1_scalar = match Option::from(<Helios as Ciphersuite>::F::from_repr(x.to_repr())) {
          Some(s) => s,
          None => {
            fcmp_dbg("fcmp_pp_prove: path check failed (c1 scalar)");
            return;
          }
        };
        if !curve_2_layers[c2_idx].iter().any(|s| s == &c1_scalar) {
          fcmp_dbg("fcmp_pp_prove: path check missing c1 hash in curve_2 layer");
        }
        let current_c2 = c2_hash_scalars(&curve_2_layers[c2_idx]);
        c2_idx += 1;
        if c1_idx >= curve_1_layers.len() {
          computed_root_type = 2;
          computed_root_bytes = current_c2.to_bytes();
          break;
        }

        let (x2, _) = <Helios as Ciphersuite>::G::to_xy(current_c2).unwrap();
        let c2_scalar = match Option::from(<Selene as Ciphersuite>::F::from_repr(x2.to_repr())) {
          Some(s) => s,
          None => {
            fcmp_dbg("fcmp_pp_prove: path check failed (c2 scalar)");
            return;
          }
        };
        if !curve_1_layers[c1_idx].iter().any(|s| s == &c2_scalar) {
          fcmp_dbg("fcmp_pp_prove: path check missing c2 hash in curve_1 layer");
        }
        current_c1 = c1_hash_scalars(&curve_1_layers[c1_idx]);
        c1_idx += 1;

        if c2_idx >= curve_2_layers.len() {
          computed_root_type = 1;
          computed_root_bytes = current_c1.to_bytes();
          break;
        }
      } else {
        fcmp_dbg("fcmp_pp_prove: path check missing curve_2 layer");
        break;
      }
    }
  }

  if computed_root_type != root_type || computed_root_bytes != *root_bytes {
    fcmp_dbg("fcmp_pp_prove: path check root mismatch");
  } else {
    fcmp_dbg("fcmp_pp_prove: path check root ok");
  }
}

fn write_u32(buf: &mut Vec<u8>, value: u32) {
  buf.extend_from_slice(&value.to_le_bytes());
}

fn append_scalar<F: PrimeField>(buf: &mut Vec<u8>, value: F) {
  buf.extend_from_slice(value.to_repr().as_ref());
}

#[no_mangle]
pub extern "C" fn fcmp_hash_c1_leaves(
  outputs_ptr: *const u8,
  outputs_len: usize,
  out_ptr: *mut u8,
  out_len: usize,
) -> i32 {
  if outputs_ptr.is_null() || out_ptr.is_null() {
    return 0;
  }
  if outputs_len % 96 != 0 || out_len != 32 {
    return 0;
  }
  let count = outputs_len / 96;
  if count == 0 || count > LAYER_ONE_LEN {
    return 0;
  }
  let outputs_bytes = unsafe { std::slice::from_raw_parts(outputs_ptr, outputs_len) };
  let mut outputs = Vec::with_capacity(count);
  for chunk in outputs_bytes.chunks_exact(96) {
    match read_output_tuple(chunk) {
      Ok(o) => outputs.push(o),
      Err(_) => return 0,
    }
  }
  let node = c1_hash_leaves(&outputs);
  unsafe {
    std::ptr::copy_nonoverlapping(node.to_bytes().as_ref().as_ptr(), out_ptr, 32);
  }
  1
}

fn read_u32(bytes: &[u8]) -> io::Result<u32> {
  if bytes.len() < 4 {
    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "u32"));
  }
  Ok(u32::from_le_bytes(bytes[0..4].try_into().unwrap()))
}

fn hex(bytes: &[u8]) -> String {
  bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn fcmp_dbg(msg: &str) {
  if let Ok(mut file) = std::fs::OpenOptions::new()
    .create(true)
    .append(true)
    .open("/root/MoneroUSD/fcmp_ffi_debug.log")
  {
    let _ = writeln!(file, "{}", msg);
  }
}

fn parse_path(bytes: &[u8], output: Output) -> io::Result<(Path<Curves>, u8, [u8; 32], u32)> {
  if bytes.len() < (1 + 4 + 32 + 4) {
    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "path header"));
  }
  let root_type = bytes[0];
  let layers = read_u32(&bytes[1..5])?;
  let mut root_bytes = [0u8; 32];
  root_bytes.copy_from_slice(&bytes[5..37]);
  let mut offset = 37;

  let leaves_len = read_u32(&bytes[offset..])? as usize;
  offset += 4;
  if bytes.len() < offset + (leaves_len * 96) {
    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "leaves"));
  }
  let mut leaves = Vec::with_capacity(leaves_len);
  for chunk in bytes[offset..offset + (leaves_len * 96)].chunks_exact(96) {
    leaves.push(read_output_tuple(chunk)?);
  }
  offset += leaves_len * 96;

  let mut found_idx: Option<usize> = None;
  for (idx, leaf) in leaves.iter().enumerate() {
    if leaf.O().to_bytes() == output.O().to_bytes()
      && leaf.I().to_bytes() == output.I().to_bytes()
      && leaf.C().to_bytes() == output.C().to_bytes()
    {
      found_idx = Some(idx);
      break;
    }
  }
  match found_idx {
    Some(idx) => {
      fcmp_dbg(&format!("fcmp_pp_prove: leaf_index={}/{}", idx, leaves_len));
    }
    None => {
      fcmp_dbg("fcmp_pp_prove: output tuple not found in path leaves");
      return Err(io::Error::new(io::ErrorKind::InvalidData, "output not in leaves"));
    }
  }

  let c2_layers_len = read_u32(&bytes[offset..])? as usize;
  offset += 4;
  let mut curve_2_layers: Vec<Vec<<Helios as Ciphersuite>::F>> = Vec::with_capacity(c2_layers_len);
  for _ in 0..c2_layers_len {
    let layer_len = read_u32(&bytes[offset..])? as usize;
    offset += 4;
    if bytes.len() < offset + (layer_len * 32) {
      return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "curve_2 layer"));
    }
    let mut layer = Vec::with_capacity(layer_len);
    for chunk in bytes[offset..offset + (layer_len * 32)].chunks_exact(32) {
      let mut repr = <<Helios as Ciphersuite>::F as PrimeField>::Repr::default();
      repr.as_mut().copy_from_slice(chunk);
      let scalar = Option::from(<Helios as Ciphersuite>::F::from_repr(repr))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "curve_2 scalar"))?;
      layer.push(scalar);
    }
    offset += layer_len * 32;
    curve_2_layers.push(layer);
  }

  let c1_layers_len = read_u32(&bytes[offset..])? as usize;
  offset += 4;
  let mut curve_1_layers: Vec<Vec<<Selene as Ciphersuite>::F>> = Vec::with_capacity(c1_layers_len);
  for _ in 0..c1_layers_len {
    let layer_len = read_u32(&bytes[offset..])? as usize;
    offset += 4;
    if bytes.len() < offset + (layer_len * 32) {
      return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "curve_1 layer"));
    }
    let mut layer = Vec::with_capacity(layer_len);
    for chunk in bytes[offset..offset + (layer_len * 32)].chunks_exact(32) {
      let mut repr = <<Selene as Ciphersuite>::F as PrimeField>::Repr::default();
      repr.as_mut().copy_from_slice(chunk);
      let scalar = Option::from(<Selene as Ciphersuite>::F::from_repr(repr))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "curve_1 scalar"))?;
      layer.push(scalar);
    }
    offset += layer_len * 32;
    curve_1_layers.push(layer);
  }

  let path = Path::<Curves> {
    output,
    leaves,
    curve_2_layers,
    curve_1_layers,
  };
  Ok((path, root_type, root_bytes, layers))
}

#[no_mangle]
pub extern "C" fn fcmp_pp_prove(
  inputs_ptr: *const u8,
  inputs_len: usize,
  pseudo_outs_ptr: *const u8,
  pseudo_outs_len: usize,
  signable_hash_ptr: *const u8,
  signable_hash_len: usize,
  out_proof_ptr: *mut *mut u8,
  out_proof_len: *mut usize,
  out_tree_root_ptr: *mut u8,
  out_tree_root_len: usize,
  out_tree_root_type: *mut u8,
  out_layers: *mut u32,
  out_key_images_ptr: *mut u8,
  out_key_images_len: usize,
  out_c_tildes_ptr: *mut u8,
  out_c_tildes_len: usize,
) -> i32 {
  if inputs_ptr.is_null()
    || pseudo_outs_ptr.is_null()
    || signable_hash_ptr.is_null()
    || out_proof_ptr.is_null()
    || out_proof_len.is_null()
    || out_tree_root_ptr.is_null()
    || out_tree_root_type.is_null()
    || out_layers.is_null()
    || out_key_images_ptr.is_null()
    || out_c_tildes_ptr.is_null()
  {
    fcmp_dbg("fcmp_pp_prove: null pointer input");
    return 0;
  }
  if signable_hash_len != 32 || out_tree_root_len != 32 {
    fcmp_dbg("fcmp_pp_prove: invalid hash/root length");
    return 0;
  }
  if pseudo_outs_len % 32 != 0 {
    fcmp_dbg("fcmp_pp_prove: invalid pseudo_outs length");
    return 0;
  }

  let inputs_bytes = unsafe { std::slice::from_raw_parts(inputs_ptr, inputs_len) };
  if inputs_bytes.len() < 4 {
    fcmp_dbg("fcmp_pp_prove: inputs too short");
    return 0;
  }
  let input_count = match read_u32(inputs_bytes) {
    Ok(v) => v as usize,
    Err(_) => {
      fcmp_dbg("fcmp_pp_prove: input count read failed");
      return 0;
    }
  };
  let expected_pseudo = pseudo_outs_len / 32;
  if input_count == 0 || input_count != expected_pseudo {
    fcmp_dbg("fcmp_pp_prove: input count mismatch");
    return 0;
  }
  if out_key_images_len < input_count * 32 {
    fcmp_dbg("fcmp_pp_prove: key image buffer too small");
    return 0;
  }
  if out_c_tildes_len < input_count * 32 {
    fcmp_dbg("fcmp_pp_prove: C_tilde buffer too small");
    return 0;
  }

  let signable_hash = unsafe { std::slice::from_raw_parts(signable_hash_ptr, signable_hash_len) };
  let mut signable = [0u8; 32];
  signable.copy_from_slice(signable_hash);
  fcmp_dbg(&format!("fcmp_pp_prove: inputs={} signable={}", input_count, hex(&signable)));
  let pseudo_outs_bytes = unsafe { std::slice::from_raw_parts(pseudo_outs_ptr, pseudo_outs_len) };
  if pseudo_outs_bytes.len() >= 32 {
    fcmp_dbg(&format!(
      "fcmp_pp_prove: pseudo_out_in0={}",
      hex(&pseudo_outs_bytes[0..32])
    ));
  }
  if pseudo_outs_bytes.len() >= 64 {
    fcmp_dbg(&format!(
      "fcmp_pp_prove: pseudo_out_in1={}",
      hex(&pseudo_outs_bytes[32..64])
    ));
  }

  let mut offset = 4usize;
  let mut outputs = Vec::with_capacity(input_count);
  let mut x_scalars = Vec::with_capacity(input_count);
  let mut paths = Vec::with_capacity(input_count);
  let mut root_type: Option<u8> = None;
  let mut root_bytes: Option<[u8; 32]> = None;
  let mut layers: Option<u32> = None;

  let mut input_idx = 0usize;
  for _ in 0..input_count {
    if inputs_bytes.len() < offset + 96 + 32 + 4 {
      fcmp_dbg("fcmp_pp_prove: inputs truncated before tuple/scalar/path");
      return 0;
    }
    let output = match read_output_tuple(&inputs_bytes[offset..offset + 96]) {
      Ok(o) => o,
      Err(_) => {
        fcmp_dbg("fcmp_pp_prove: output tuple parse failed");
        return 0;
      }
    };
    offset += 96;

    if input_idx <= 1 {
      fcmp_dbg(&format!(
        "fcmp_pp_prove: input{} O={} I={} C={}",
        input_idx,
        hex(output.O().to_bytes().as_ref()),
        hex(output.I().to_bytes().as_ref()),
        hex(output.C().to_bytes().as_ref())
      ));
    }

    let x_bytes = inputs_bytes[offset..offset + 32].to_vec();
    let mut reader = &inputs_bytes[offset..offset + 32];
    let x = match Ed25519::read_F(&mut reader) {
      Ok(x) => x,
      Err(_) => {
        fcmp_dbg("fcmp_pp_prove: input scalar parse failed");
        return 0;
      }
    };
    offset += 32;

    let path_len = match read_u32(&inputs_bytes[offset..]) {
      Ok(v) => v as usize,
      Err(_) => {
        fcmp_dbg("fcmp_pp_prove: path length read failed");
        return 0;
      }
    };
    offset += 4;
    if input_idx <= 1 {
      fcmp_dbg(&format!(
        "fcmp_pp_prove: input{} x={} path_len={}",
        input_idx,
        hex(&x_bytes),
        path_len
      ));
    }
    if inputs_bytes.len() < offset + path_len {
      fcmp_dbg("fcmp_pp_prove: path bytes truncated");
      return 0;
    }
    let path_bytes = &inputs_bytes[offset..offset + path_len];
    offset += path_len;

    let (path, p_root_type, p_root_bytes, p_layers) = match parse_path(path_bytes, output) {
      Ok(v) => v,
      Err(_) => {
        fcmp_dbg(&format!("fcmp_pp_prove: path parse failed (len={})", path_len));
        return 0;
      }
    };
    if let Some(rt) = root_type {
      if rt != p_root_type {
        fcmp_dbg("fcmp_pp_prove: root type mismatch");
        return 0;
      }
    }
    if let Some(rb) = root_bytes {
      if rb != p_root_bytes {
        fcmp_dbg("fcmp_pp_prove: root bytes mismatch");
        return 0;
      }
    }
    if let Some(l) = layers {
      if l != p_layers {
        fcmp_dbg("fcmp_pp_prove: layers mismatch");
        return 0;
      }
    }
    root_type = Some(p_root_type);
    root_bytes = Some(p_root_bytes);
    layers = Some(p_layers);

    if input_idx <= 1 {
      fcmp_dbg(&format!(
        "fcmp_pp_prove: input{} root_type={} layers={}",
        input_idx,
        p_root_type,
        p_layers
      ));
      fcmp_dbg(&format!(
        "fcmp_pp_prove: input{} root={}",
        input_idx,
        hex(&p_root_bytes)
      ));
      debug_check_path(&path.leaves, &path.curve_2_layers, &path.curve_1_layers, p_root_type, &p_root_bytes);
    }

    outputs.push(path.output);
    x_scalars.push(x);
    paths.push(path);
    input_idx += 1;
  }

  let branches = match Branches::<Curves>::new(paths) {
    Some(b) => b,
    None => {
      fcmp_dbg("fcmp_pp_prove: branches construction failed");
      return 0;
    }
  };

  let mut rng = OsRng;
  let mut inputs = Vec::with_capacity(input_count);
  let mut key_images = Vec::with_capacity(input_count);
  let mut c_tildes = Vec::with_capacity(input_count);
  let mut output_blinds = Vec::with_capacity(input_count);

  for (idx, (output, x)) in outputs.iter().zip(x_scalars.iter()).enumerate() {
    let rerandomized_output = RerandomizedOutput::new(&mut rng, output.clone());
    let input_tuple = rerandomized_output.input();
    let opening = match OpenedInputTuple::open(&rerandomized_output, x, &Scalar::ZERO) {
      Some(o) => o,
      None => {
        fcmp_dbg("fcmp_pp_prove: opened input tuple failed");
        return 0;
      }
    };
    let (L, sal) = SpendAuthAndLinkability::prove(&mut rng, signable, &opening);
    if idx == 0 {
      fcmp_dbg(&format!(
        "fcmp_pp_prove: key_image0={}",
        hex(L.to_bytes().as_ref())
      ));
      fcmp_dbg(&format!(
        "fcmp_pp_prove: input0 C_tilde={}",
        hex(input_tuple.C_tilde().to_bytes().as_ref())
      ));
    }
    else if idx == 1 {
      fcmp_dbg(&format!(
        "fcmp_pp_prove: key_image1={}",
        hex(L.to_bytes().as_ref())
      ));
      fcmp_dbg(&format!(
        "fcmp_pp_prove: input1 C_tilde={}",
        hex(input_tuple.C_tilde().to_bytes().as_ref())
      ));
    }
    key_images.push(L);
    c_tildes.push(input_tuple.C_tilde());
    inputs.push((input_tuple, sal));

    let output_blind = OutputBlinds::new(
      OBlind::new(
        EdwardsPoint(*T),
        ScalarDecomposition::new(rerandomized_output.o_blind()).unwrap(),
      ),
      IBlind::new(
        EdwardsPoint(*FCMP_PLUS_PLUS_U),
        EdwardsPoint(*FCMP_PLUS_PLUS_V),
        ScalarDecomposition::new(rerandomized_output.i_blind()).unwrap(),
      ),
      IBlindBlind::new(
        EdwardsPoint(*T),
        ScalarDecomposition::new(rerandomized_output.i_blind_blind()).unwrap(),
      ),
      CBlind::new(
        EdwardsPoint::generator(),
        ScalarDecomposition::new(rerandomized_output.c_blind()).unwrap(),
      ),
    );
    let blinded_input = match output_blind.blind(output) {
      Ok(v) => v,
      Err(_) => {
        fcmp_dbg("fcmp_pp_prove: output_blinds.blind failed");
        return 0;
      }
    };
    let input_from_rerand = match fcmps::Input::new(
      input_tuple.O_tilde(),
      input_tuple.I_tilde(),
      input_tuple.R(),
      input_tuple.C_tilde(),
    ) {
      Ok(v) => v,
      Err(_) => {
        fcmp_dbg("fcmp_pp_prove: input tuple conversion failed");
        return 0;
      }
    };
    if blinded_input != input_from_rerand {
      fcmp_dbg("fcmp_pp_prove: input tuple mismatch vs output_blinds");
    }
    output_blinds.push(output_blind);
  }

  let mut branches_1_blinds = Vec::with_capacity(branches.necessary_c1_blinds());
  for _ in 0..branches.necessary_c1_blinds() {
    let scalar = <Selene as Ciphersuite>::F::random(&mut rng);
    let blind = BranchBlind::new(
      SELENE_FCMP_GENERATORS.generators.h(),
      ScalarDecomposition::new(scalar).unwrap(),
    );
    branches_1_blinds.push(blind);
  }
  let mut branches_2_blinds = Vec::with_capacity(branches.necessary_c2_blinds());
  for _ in 0..branches.necessary_c2_blinds() {
    let scalar = <Helios as Ciphersuite>::F::random(&mut rng);
    let blind = BranchBlind::new(
      HELIOS_FCMP_GENERATORS.generators.h(),
      ScalarDecomposition::new(scalar).unwrap(),
    );
    branches_2_blinds.push(blind);
  }

  let blinded_branches = match branches.blind(output_blinds, branches_1_blinds, branches_2_blinds) {
    Ok(b) => b,
    Err(_) => {
      fcmp_dbg("fcmp_pp_prove: branches blind failed");
      return 0;
    }
  };

  let fcmp = match Fcmp::prove(&mut rng, &*FCMP_PARAMS, blinded_branches) {
    Ok(p) => p,
    Err(_) => {
      fcmp_dbg("fcmp_pp_prove: Fcmp::prove failed");
      return 0;
    }
  };
  let fcmp_pp = FcmpPlusPlus::new(inputs, fcmp);

  if let (Some(rt), Some(rb), Some(layers_val)) = (root_type, root_bytes, layers) {
    let tree = match rt {
      1 => match read_point::<Selene>(&rb) {
        Ok(p) => TreeRoot::<Selene, Helios>::C1(p),
        Err(_) => {
          fcmp_dbg("fcmp_pp_prove: self-verify tree root parse failed");
          return 0;
        }
      },
      2 => match read_point::<Helios>(&rb) {
        Ok(p) => TreeRoot::<Selene, Helios>::C2(p),
        Err(_) => {
          fcmp_dbg("fcmp_pp_prove: self-verify tree root parse failed");
          return 0;
        }
      },
      _ => {
        fcmp_dbg("fcmp_pp_prove: self-verify invalid tree root type");
        return 0;
      }
    };

    let mut verify_rng = ChaCha20Rng::from_seed(signable);
    let mut ed_verifier: BatchVerifier<(), <Ed25519 as Ciphersuite>::G> = BatchVerifier::new(1);
    let mut c1_verifier = GbGenerators::<Selene>::batch_verifier();
    let mut c2_verifier = GbGenerators::<Helios>::batch_verifier();
    if fcmp_pp.verify(
      &mut verify_rng,
      &mut ed_verifier,
      &mut c1_verifier,
      &mut c2_verifier,
      tree,
      layers_val as usize,
      signable,
      key_images.clone(),
    ).is_err()
    {
      fcmp_dbg("fcmp_pp_prove: self-verify failed");
    }
    else if !ed_verifier.verify_vartime() {
      fcmp_dbg("fcmp_pp_prove: self-verify ed_verifier failed");
    }
    else if !SELENE_FCMP_GENERATORS.generators.verify(c1_verifier) {
      fcmp_dbg("fcmp_pp_prove: self-verify c1_verifier failed");
    }
    else if !HELIOS_FCMP_GENERATORS.generators.verify(c2_verifier) {
      fcmp_dbg("fcmp_pp_prove: self-verify c2_verifier failed");
    }
  }
  else {
    fcmp_dbg("fcmp_pp_prove: self-verify missing root info");
  }

  let mut proof_buf = Vec::new();
  if fcmp_pp.write(&mut proof_buf).is_err() {
    fcmp_dbg("fcmp_pp_prove: proof write failed");
    return 0;
  }

  if let (Some(rt), Some(rb), Some(layers_val)) = (root_type, root_bytes, layers) {
    let tree = match rt {
      1 => match read_point::<Selene>(&rb) {
        Ok(p) => TreeRoot::<Selene, Helios>::C1(p),
        Err(_) => {
          fcmp_dbg("fcmp_pp_prove: self-verify (serialized) tree root parse failed");
          return 0;
        }
      },
      2 => match read_point::<Helios>(&rb) {
        Ok(p) => TreeRoot::<Selene, Helios>::C2(p),
        Err(_) => {
          fcmp_dbg("fcmp_pp_prove: self-verify (serialized) tree root parse failed");
          return 0;
        }
      },
      _ => {
        fcmp_dbg("fcmp_pp_prove: self-verify (serialized) invalid tree root type");
        return 0;
      }
    };

    let mut c_tildes_bytes = Vec::with_capacity(c_tildes.len());
    for ct in &c_tildes {
      let mut buf = [0u8; 32];
      buf.copy_from_slice(ct.to_bytes().as_ref());
      c_tildes_bytes.push(buf);
    }

    let mut reader = proof_buf.as_slice();
    let decoded = FcmpPlusPlus::read(&c_tildes_bytes, layers_val as usize, &mut reader);
    match decoded {
      Ok(decoded_pp) => {
        let mut verify_rng = ChaCha20Rng::from_seed(signable);
        let mut ed_verifier: BatchVerifier<(), <Ed25519 as Ciphersuite>::G> = BatchVerifier::new(1);
        let mut c1_verifier = GbGenerators::<Selene>::batch_verifier();
        let mut c2_verifier = GbGenerators::<Helios>::batch_verifier();
        if decoded_pp.verify(
          &mut verify_rng,
          &mut ed_verifier,
          &mut c1_verifier,
          &mut c2_verifier,
          tree,
          layers_val as usize,
          signable,
          key_images.clone(),
        ).is_err()
        {
          fcmp_dbg("fcmp_pp_prove: self-verify (serialized) failed");
        }
        else if !ed_verifier.verify_vartime() {
          fcmp_dbg("fcmp_pp_prove: self-verify (serialized) ed_verifier failed");
        }
        else if !SELENE_FCMP_GENERATORS.generators.verify(c1_verifier) {
          fcmp_dbg("fcmp_pp_prove: self-verify (serialized) c1_verifier failed");
        }
        else if !HELIOS_FCMP_GENERATORS.generators.verify(c2_verifier) {
          fcmp_dbg("fcmp_pp_prove: self-verify (serialized) c2_verifier failed");
        }
      }
      Err(_) => {
        fcmp_dbg("fcmp_pp_prove: self-verify (serialized) read failed");
      }
    }
  }

  let mut boxed = proof_buf.into_boxed_slice();
  let ptr = boxed.as_mut_ptr();
  let len = boxed.len();
  if len == 0 {
    fcmp_dbg("fcmp_pp_prove: proof length is 0");
  }
  std::mem::forget(boxed);

  unsafe {
    *out_proof_ptr = ptr;
    *out_proof_len = len;
    *out_tree_root_type = root_type.unwrap_or(0);
    *out_layers = layers.unwrap_or(0);
    out_tree_root_ptr.copy_from_nonoverlapping(root_bytes.unwrap_or([0u8; 32]).as_ptr(), 32);
    let key_images_bytes = std::slice::from_raw_parts_mut(out_key_images_ptr, input_count * 32);
    for (i, ki) in key_images.iter().enumerate() {
      key_images_bytes[i * 32..(i + 1) * 32].copy_from_slice(ki.to_bytes().as_ref());
    }
    let c_tildes_bytes = std::slice::from_raw_parts_mut(out_c_tildes_ptr, input_count * 32);
    for (i, ct) in c_tildes.iter().enumerate() {
      c_tildes_bytes[i * 32..(i + 1) * 32].copy_from_slice(ct.to_bytes().as_ref());
    }
  }

  1
}

#[no_mangle]
pub extern "C" fn fcmp_tree_path(
  outputs_ptr: *const u8,
  outputs_len: usize,
  target_index: usize,
  out_ptr: *mut *mut u8,
  out_len: *mut usize,
) -> i32 {
  if outputs_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
    return 0;
  }
  if outputs_len % 96 != 0 {
    return 0;
  }
  let outputs_bytes = unsafe { std::slice::from_raw_parts(outputs_ptr, outputs_len) };
  let count = outputs_len / 96;
  if count == 0 || target_index >= count {
    return 0;
  }

  let mut outputs = Vec::with_capacity(count);
  for chunk in outputs_bytes.chunks_exact(96) {
    match read_output_tuple(chunk) {
      Ok(o) => outputs.push(o),
      Err(_) => return 0,
    }
  }

  let target_group = target_index / LAYER_ONE_LEN;
  let leaves_start = target_group * LAYER_ONE_LEN;
  let leaves_end = usize::min(outputs.len(), leaves_start + LAYER_ONE_LEN);
  let leaves = outputs[leaves_start..leaves_end].to_vec();

  let mut c1_nodes = Vec::new();
  for chunk in outputs.chunks(LAYER_ONE_LEN) {
    c1_nodes.push(c1_hash_leaves(chunk));
  }

  let mut layers = 1u32;
  let mut curve_2_layers: Vec<Vec<<Helios as Ciphersuite>::F>> = vec![];
  let mut curve_1_layers: Vec<Vec<<Selene as Ciphersuite>::F>> = vec![];

  let mut root = TreeRoot::<Selene, Helios>::C1(*c1_nodes.first().unwrap());
  let mut target_idx = target_group;
  while c1_nodes.len() > 1 {
      let mut c2_nodes: Vec<<Helios as Ciphersuite>::G> = vec![];
      let mut branch: Vec<<Helios as Ciphersuite>::F> = vec![];
      let group_idx = target_idx / LAYER_TWO_LEN;
      for (idx, chunk) in c1_nodes.chunks(LAYER_TWO_LEN).enumerate() {
      if idx == group_idx {
        branch = chunk.iter().map(|p| {
          let (x, _) = <Selene as Ciphersuite>::G::to_xy(*p).unwrap();
          <Helios as Ciphersuite>::F::from_repr(x.to_repr()).unwrap()
        }).collect();
        while branch.len() < LAYER_TWO_LEN {
          branch.push(<Helios as Ciphersuite>::F::ZERO);
        }
      }
      c2_nodes.push(c2_hash_nodes(chunk));
    }
      curve_2_layers.push(branch);
      c1_nodes = vec![];
      layers += 1;
      target_idx = group_idx;
      root = TreeRoot::<Selene, Helios>::C2(*c2_nodes.first().unwrap());
      if c2_nodes.len() == 1 {
        break;
      }
      let mut next_c1: Vec<<Selene as Ciphersuite>::G> = vec![];
      let mut branch_c1: Vec<<Selene as Ciphersuite>::F> = vec![];
      let group_idx_c1 = target_idx / LAYER_ONE_LEN;
      for (idx, chunk) in c2_nodes.chunks(LAYER_ONE_LEN).enumerate() {
        if idx == group_idx_c1 {
          branch_c1 = chunk.iter().map(|p| {
            let (x, _) = <Helios as Ciphersuite>::G::to_xy(*p).unwrap();
            <Selene as Ciphersuite>::F::from_repr(x.to_repr()).unwrap()
          }).collect();
        }
        next_c1.push(c1_hash_nodes(chunk));
      }
      curve_1_layers.push(branch_c1);
      layers += 1;
      target_idx = group_idx_c1;
      c1_nodes = next_c1;
      root = TreeRoot::<Selene, Helios>::C1(*c1_nodes.first().unwrap());
      if c1_nodes.len() == 1 {
        break;
      }
  }

  let (root_type, root_bytes): (u8, Vec<u8>) = match root {
    TreeRoot::C1(p) => (1u8, p.to_bytes().as_ref().to_vec()),
    TreeRoot::C2(p) => (2u8, p.to_bytes().as_ref().to_vec()),
  };

  let mut buf = Vec::new();
  buf.push(root_type);
  write_u32(&mut buf, layers);
  buf.extend_from_slice(&root_bytes);

  write_u32(&mut buf, leaves.len() as u32);
  for leaf in &leaves {
    buf.extend_from_slice(leaf.O().to_bytes().as_ref());
    buf.extend_from_slice(leaf.I().to_bytes().as_ref());
    buf.extend_from_slice(leaf.C().to_bytes().as_ref());
  }

  write_u32(&mut buf, curve_2_layers.len() as u32);
  for layer in &curve_2_layers {
    write_u32(&mut buf, layer.len() as u32);
    for scalar in layer {
      append_scalar(&mut buf, *scalar);
    }
  }

  write_u32(&mut buf, curve_1_layers.len() as u32);
  for layer in &curve_1_layers {
    write_u32(&mut buf, layer.len() as u32);
    for scalar in layer {
      append_scalar(&mut buf, *scalar);
    }
  }

  let mut boxed = buf.into_boxed_slice();
  let ptr = boxed.as_mut_ptr();
  let len = boxed.len();
  std::mem::forget(boxed);

  unsafe {
    *out_ptr = ptr;
    *out_len = len;
  }
  1
}

#[no_mangle]
pub extern "C" fn fcmp_tree_path_from_c1(
  outputs_ptr: *const u8,
  outputs_len: usize,
  c1_nodes_ptr: *const u8,
  c1_nodes_len: usize,
  target_group_index: usize,
  out_ptr: *mut *mut u8,
  out_len: *mut usize,
) -> i32 {
  if outputs_ptr.is_null() || c1_nodes_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
    return 0;
  }
  if outputs_len % 96 != 0 || c1_nodes_len % 32 != 0 {
    return 0;
  }
  let count = outputs_len / 96;
  if count == 0 || count > LAYER_ONE_LEN {
    return 0;
  }
  let c1_count = c1_nodes_len / 32;
  if c1_count == 0 || target_group_index >= c1_count {
    return 0;
  }

  let outputs_bytes = unsafe { std::slice::from_raw_parts(outputs_ptr, outputs_len) };
  let mut outputs = Vec::with_capacity(count);
  for chunk in outputs_bytes.chunks_exact(96) {
    match read_output_tuple(chunk) {
      Ok(o) => outputs.push(o),
      Err(_) => return 0,
    }
  }

  let c1_nodes_bytes = unsafe { std::slice::from_raw_parts(c1_nodes_ptr, c1_nodes_len) };
  let mut c1_nodes = Vec::with_capacity(c1_count);
  for chunk in c1_nodes_bytes.chunks_exact(32) {
    match read_point::<Selene>(chunk) {
      Ok(p) => c1_nodes.push(p),
      Err(_) => return 0,
    }
  }

  let leaf_hash = c1_hash_leaves(&outputs);
  if c1_nodes[target_group_index] != leaf_hash {
    return 0;
  }

  let mut curve_2_layers: Vec<Vec<<Helios as Ciphersuite>::F>> = vec![];
  let mut curve_1_layers: Vec<Vec<<Selene as Ciphersuite>::F>> = vec![];
  let mut layers = 1u32;
  let mut target_idx = target_group_index;

  let mut root = TreeRoot::<Selene, Helios>::C1(*c1_nodes.first().unwrap());
  while c1_nodes.len() > 1 {
    let mut c2_nodes: Vec<<Helios as Ciphersuite>::G> = vec![];
    let mut branch: Vec<<Helios as Ciphersuite>::F> = vec![];
    let group_idx = target_idx / LAYER_TWO_LEN;
    for (idx, chunk) in c1_nodes.chunks(LAYER_TWO_LEN).enumerate() {
      if idx == group_idx {
        branch = chunk.iter().map(|p| {
          let (x, _) = <Selene as Ciphersuite>::G::to_xy(*p).unwrap();
          <Helios as Ciphersuite>::F::from_repr(x.to_repr()).unwrap()
        }).collect();
        while branch.len() < LAYER_TWO_LEN {
          branch.push(<Helios as Ciphersuite>::F::ZERO);
        }
      }
      c2_nodes.push(c2_hash_nodes(chunk));
    }
    curve_2_layers.push(branch);
    layers += 1;
    target_idx = group_idx;
    root = TreeRoot::<Selene, Helios>::C2(*c2_nodes.first().unwrap());
    if c2_nodes.len() == 1 {
      break;
    }

    let mut next_c1: Vec<<Selene as Ciphersuite>::G> = vec![];
    let mut branch_c1: Vec<<Selene as Ciphersuite>::F> = vec![];
    let group_idx_c1 = target_idx / LAYER_ONE_LEN;
    for (idx, chunk) in c2_nodes.chunks(LAYER_ONE_LEN).enumerate() {
      if idx == group_idx_c1 {
        branch_c1 = chunk.iter().map(|p| {
          let (x, _) = <Helios as Ciphersuite>::G::to_xy(*p).unwrap();
          <Selene as Ciphersuite>::F::from_repr(x.to_repr()).unwrap()
        }).collect();
        while branch_c1.len() < LAYER_ONE_LEN {
          branch_c1.push(<Selene as Ciphersuite>::F::ZERO);
        }
      }
      next_c1.push(c1_hash_nodes(chunk));
    }
    curve_1_layers.push(branch_c1);
    layers += 1;
    target_idx = group_idx_c1;
    c1_nodes = next_c1;
    root = TreeRoot::<Selene, Helios>::C1(*c1_nodes.first().unwrap());
  }

  let (root_type, root_bytes) = match root {
    TreeRoot::C1(p) => (1u8, p.to_bytes()),
    TreeRoot::C2(p) => (2u8, p.to_bytes()),
  };

  let mut buf = Vec::new();
  buf.push(root_type);
  write_u32(&mut buf, layers);
  buf.extend_from_slice(root_bytes.as_ref());

  write_u32(&mut buf, outputs.len() as u32);
  for leaf in &outputs {
    buf.extend_from_slice(leaf.O().to_bytes().as_ref());
    buf.extend_from_slice(leaf.I().to_bytes().as_ref());
    buf.extend_from_slice(leaf.C().to_bytes().as_ref());
  }

  write_u32(&mut buf, curve_2_layers.len() as u32);
  for layer in &curve_2_layers {
    write_u32(&mut buf, layer.len() as u32);
    for scalar in layer {
      append_scalar(&mut buf, *scalar);
    }
  }

  write_u32(&mut buf, curve_1_layers.len() as u32);
  for layer in &curve_1_layers {
    write_u32(&mut buf, layer.len() as u32);
    for scalar in layer {
      append_scalar(&mut buf, *scalar);
    }
  }

  let mut boxed = buf.into_boxed_slice();
  let ptr = boxed.as_mut_ptr();
  let len = boxed.len();
  std::mem::forget(boxed);

  unsafe {
    *out_ptr = ptr;
    *out_len = len;
  }
  1
}

#[no_mangle]
pub extern "C" fn fcmp_free(ptr: *mut u8, len: usize) {
  if ptr.is_null() || len == 0 {
    return;
  }
  unsafe {
    let _ = Box::from_raw(std::slice::from_raw_parts_mut(ptr, len) as *mut [u8]);
  }
}

#[no_mangle]
pub extern "C" fn fcmp_pp_verify(
  proof_ptr: *const u8,
  proof_len: usize,
  pseudo_outs_ptr: *const u8,
  pseudo_outs_len: usize,
  tree_root_ptr: *const u8,
  tree_root_len: usize,
  tree_root_type: u8,
  layers: u32,
  signable_hash_ptr: *const u8,
  signable_hash_len: usize,
  key_images_ptr: *const u8,
  key_images_len: usize,
) -> i32 {
  if proof_ptr.is_null()
    || pseudo_outs_ptr.is_null()
    || tree_root_ptr.is_null()
    || signable_hash_ptr.is_null()
    || key_images_ptr.is_null()
  {
    fcmp_dbg("fcmp_pp_verify: null pointer input");
    return -1;
  }

  if signable_hash_len != 32 || tree_root_len != 32 {
    fcmp_dbg("fcmp_pp_verify: invalid hash/root length");
    return -2;
  }

  if pseudo_outs_len % 32 != 0 || key_images_len % 32 != 0 {
    fcmp_dbg("fcmp_pp_verify: invalid c_tilde/key_images length");
    return -3;
  }

  let inputs = pseudo_outs_len / 32;
  if inputs == 0 || inputs != key_images_len / 32 {
    fcmp_dbg("fcmp_pp_verify: input count mismatch");
    return -4;
  }

  let proof = unsafe { std::slice::from_raw_parts(proof_ptr, proof_len) };
  let pseudo_outs_bytes = unsafe { std::slice::from_raw_parts(pseudo_outs_ptr, pseudo_outs_len) };
  let tree_root_bytes = unsafe { std::slice::from_raw_parts(tree_root_ptr, tree_root_len) };
  let signable_hash_bytes = unsafe { std::slice::from_raw_parts(signable_hash_ptr, signable_hash_len) };
  let key_images_bytes = unsafe { std::slice::from_raw_parts(key_images_ptr, key_images_len) };

  let mut pseudo_outs = Vec::with_capacity(inputs);
  for chunk in pseudo_outs_bytes.chunks_exact(32) {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(chunk);
    pseudo_outs.push(buf);
  }

  let tree = match tree_root_type {
    1 => match read_point::<Selene>(tree_root_bytes) {
      Ok(p) => TreeRoot::<Selene, Helios>::C1(p),
      Err(_) => {
        fcmp_dbg("fcmp_pp_verify: C1 tree root parse failed");
        return -5;
      }
    },
    2 => match read_point::<Helios>(tree_root_bytes) {
      Ok(p) => TreeRoot::<Selene, Helios>::C2(p),
      Err(_) => {
        fcmp_dbg("fcmp_pp_verify: C2 tree root parse failed");
        return -6;
      }
    },
    _ => {
      fcmp_dbg("fcmp_pp_verify: invalid tree root type");
      return -7;
    }
  };

  let mut signable_hash = [0u8; 32];
  signable_hash.copy_from_slice(signable_hash_bytes);
  fcmp_dbg(&format!(
    "fcmp_pp_verify: inputs={} tree_type={} layers={} signable={}",
    inputs,
    tree_root_type,
    layers,
    hex(&signable_hash)
  ));
  fcmp_dbg(&format!("fcmp_pp_verify: tree_root={}", hex(tree_root_bytes)));
  if !pseudo_outs.is_empty() {
    fcmp_dbg(&format!(
      "fcmp_pp_verify: c_tilde0={}",
      hex(&pseudo_outs[0])
    ));
  }
  if pseudo_outs.len() > 1 {
    fcmp_dbg(&format!(
      "fcmp_pp_verify: c_tilde1={}",
      hex(&pseudo_outs[1])
    ));
  }
  fcmp_dbg(&format!(
    "fcmp_pp_verify: inputs={} proof_len={} signable={}",
    inputs,
    proof_len,
    hex(&signable_hash)
  ));

  let mut key_images = Vec::with_capacity(inputs);
  for chunk in key_images_bytes.chunks_exact(32) {
    let mut reader = chunk;
    match Ed25519::read_G(&mut reader) {
      Ok(p) => key_images.push(p),
      Err(_) => {
        fcmp_dbg("fcmp_pp_verify: key image parse failed");
        return -8;
      }
    }
  }
  if !key_images.is_empty() {
    fcmp_dbg(&format!(
      "fcmp_pp_verify: key_image0={}",
      hex(key_images[0].to_bytes().as_ref())
    ));
  }
  if key_images.len() > 1 {
    fcmp_dbg(&format!(
      "fcmp_pp_verify: key_image1={}",
      hex(key_images[1].to_bytes().as_ref())
    ));
  }
  if let Some(ki0) = key_images.first() {
    fcmp_dbg(&format!(
      "fcmp_pp_verify: key_image0={}",
      hex(ki0.to_bytes().as_ref())
    ));
  }

  let mut proof_reader = proof;
  let proof = match FcmpPlusPlus::read(&pseudo_outs, layers as usize, &mut proof_reader) {
    Ok(p) => p,
    Err(_) => {
      fcmp_dbg("fcmp_pp_verify: proof parse failed");
      return -9;
    }
  };

  let mut rng = ChaCha20Rng::from_seed(signable_hash);
  let mut ed_verifier: BatchVerifier<(), <Ed25519 as Ciphersuite>::G> = BatchVerifier::new(1);
  let mut c1_verifier = GbGenerators::<Selene>::batch_verifier();
  let mut c2_verifier = GbGenerators::<Helios>::batch_verifier();

  if proof
    .verify(
      &mut rng,
      &mut ed_verifier,
      &mut c1_verifier,
      &mut c2_verifier,
      tree,
      layers as usize,
      signable_hash,
      key_images,
    )
    .is_err()
  {
    fcmp_dbg("fcmp_pp_verify: proof.verify failed");
    return -10;
  }

  if !ed_verifier.verify_vartime() {
    fcmp_dbg("fcmp_pp_verify: ed_verifier failed");
    return -11;
  }
  if !SELENE_FCMP_GENERATORS.generators.verify(c1_verifier) {
    fcmp_dbg("fcmp_pp_verify: c1_verifier failed");
    return -12;
  }
  if !HELIOS_FCMP_GENERATORS.generators.verify(c2_verifier) {
    fcmp_dbg("fcmp_pp_verify: c2_verifier failed");
    return -13;
  }

  1
}
