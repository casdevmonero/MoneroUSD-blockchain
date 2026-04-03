
          /// The FCMP generators for Selene.
          pub static SELENE_FCMP_GENERATORS:
            std_shims::sync::LazyLock<monero_generators::FcmpGenerators<helioselene::Selene>> =
              std_shims::sync::LazyLock::new(|| monero_generators::FcmpGenerators {
                generators: generalized_bulletproofs::Generators::new(
                  
        helioselene::SelenePoint::from_xy(
          <
            <helioselene::SelenePoint as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr([86, 190, 211, 180, 244, 21, 159, 165, 197, 123, 234, 132, 236, 147, 126, 96, 192, 74, 125, 138, 187, 248, 221, 208, 251, 31, 92, 91, 100, 192, 71, 9]).expect("build script x wasn't reduced"),
          <
            <helioselene::SelenePoint as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr([56, 245, 144, 78, 216, 54, 106, 83, 220, 130, 203, 11, 178, 22, 180, 157, 8, 86, 33, 255, 149, 199, 82, 9, 104, 48, 233, 130, 233, 60, 62, 57]).expect("build script y wasn't reduced"),
        ).expect("generator from build script wasn't on-curve")
      ,
                  
        helioselene::SelenePoint::from_xy(
          <
            <helioselene::SelenePoint as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr([42, 13, 222, 21, 48, 68, 246, 155, 33, 199, 67, 82, 37, 145, 130, 179, 47, 181, 96, 172, 18, 96, 131, 54, 249, 41, 39, 165, 255, 130, 229, 9]).expect("build script x wasn't reduced"),
          <
            <helioselene::SelenePoint as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr([130, 14, 34, 231, 2, 195, 46, 184, 238, 103, 229, 79, 123, 57, 16, 119, 84, 81, 3, 241, 201, 163, 108, 13, 77, 25, 106, 189, 215, 178, 99, 19]).expect("build script y wasn't reduced"),
        ).expect("generator from build script wasn't on-curve")
      ,
                  
        {
          const BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/selene_generators_g_bold"));
          let mut bytes = BYTES;
          let mut x = [0; 32];
          let mut y = [0; 32];
          let mut res = Vec::with_capacity(65536);
          while !bytes.is_empty() {
            x.copy_from_slice(&bytes[.. 32]);
            bytes = &bytes[32 ..];
            y.copy_from_slice(&bytes[.. 32]);
            bytes = &bytes[32 ..];
            res.push(
        helioselene::SelenePoint::from_xy(
          <
            <helioselene::SelenePoint as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr(x).expect("build script x wasn't reduced"),
          <
            <helioselene::SelenePoint as ec_divisors::DivisorCurve>::FieldElement
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
          const BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/selene_generators_h_bold"));
          let mut bytes = BYTES;
          let mut x = [0; 32];
          let mut y = [0; 32];
          let mut res = Vec::with_capacity(65536);
          while !bytes.is_empty() {
            x.copy_from_slice(&bytes[.. 32]);
            bytes = &bytes[32 ..];
            y.copy_from_slice(&bytes[.. 32]);
            bytes = &bytes[32 ..];
            res.push(
        helioselene::SelenePoint::from_xy(
          <
            <helioselene::SelenePoint as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr(x).expect("build script x wasn't reduced"),
          <
            <helioselene::SelenePoint as ec_divisors::DivisorCurve>::FieldElement
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
        