
          /// The FCMP generators for Helios.
          pub static HELIOS_FCMP_GENERATORS:
            std_shims::sync::LazyLock<monero_generators::FcmpGenerators<helioselene::Helios>> =
              std_shims::sync::LazyLock::new(|| monero_generators::FcmpGenerators {
                generators: generalized_bulletproofs::Generators::new(
                  
        helioselene::HeliosPoint::from_xy(
          <
            <helioselene::HeliosPoint as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr([48, 5, 228, 140, 37, 138, 92, 69, 44, 247, 180, 31, 105, 17, 66, 161, 89, 165, 220, 190, 216, 99, 87, 184, 204, 78, 217, 100, 15, 147, 141, 126]).expect("build script x wasn't reduced"),
          <
            <helioselene::HeliosPoint as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr([30, 167, 226, 178, 165, 182, 47, 117, 9, 238, 187, 220, 242, 107, 213, 127, 41, 174, 161, 89, 142, 2, 135, 18, 194, 9, 205, 224, 42, 200, 178, 97]).expect("build script y wasn't reduced"),
        ).expect("generator from build script wasn't on-curve")
      ,
                  
        helioselene::HeliosPoint::from_xy(
          <
            <helioselene::HeliosPoint as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr([44, 63, 122, 172, 29, 61, 39, 76, 6, 1, 139, 125, 208, 22, 230, 178, 6, 94, 240, 14, 33, 55, 69, 78, 140, 143, 82, 10, 19, 137, 94, 104]).expect("build script x wasn't reduced"),
          <
            <helioselene::HeliosPoint as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr([169, 5, 150, 194, 73, 57, 2, 251, 246, 44, 228, 21, 106, 132, 148, 179, 211, 210, 157, 8, 47, 216, 249, 119, 199, 116, 145, 104, 102, 79, 242, 62]).expect("build script y wasn't reduced"),
        ).expect("generator from build script wasn't on-curve")
      ,
                  
        {
          const BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/helios_generators_g_bold"));
          let mut bytes = BYTES;
          let mut x = [0; 32];
          let mut y = [0; 32];
          let mut res = Vec::with_capacity(32768);
          while !bytes.is_empty() {
            x.copy_from_slice(&bytes[.. 32]);
            bytes = &bytes[32 ..];
            y.copy_from_slice(&bytes[.. 32]);
            bytes = &bytes[32 ..];
            res.push(
        helioselene::HeliosPoint::from_xy(
          <
            <helioselene::HeliosPoint as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr(x).expect("build script x wasn't reduced"),
          <
            <helioselene::HeliosPoint as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr(y).expect("build script y wasn't reduced"),
        ).expect("generator from build script wasn't on-curve")
      );
          }
          res
        }
      ,
                  
        {
          const BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/helios_generators_h_bold"));
          let mut bytes = BYTES;
          let mut x = [0; 32];
          let mut y = [0; 32];
          let mut res = Vec::with_capacity(32768);
          while !bytes.is_empty() {
            x.copy_from_slice(&bytes[.. 32]);
            bytes = &bytes[32 ..];
            y.copy_from_slice(&bytes[.. 32]);
            bytes = &bytes[32 ..];
            res.push(
        helioselene::HeliosPoint::from_xy(
          <
            <helioselene::HeliosPoint as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr(x).expect("build script x wasn't reduced"),
          <
            <helioselene::HeliosPoint as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr(y).expect("build script y wasn't reduced"),
        ).expect("generator from build script wasn't on-curve")
      );
          }
          res
        }
      ,
                ).unwrap()
              });
        