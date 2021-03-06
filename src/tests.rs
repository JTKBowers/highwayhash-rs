use std::process::exit;

use highway_hash_64;
use highway_hash_128;


const TEST_KEY_1: [u64; 4] = [
  0x0706050403020100, 0x0F0E0D0C0B0A0908,
  0x1716151413121110, 0x1F1E1D1C1B1A1918
];

const TEST_KEY_2: [u64; 4] = [
  1, 2, 3, 4
];

const EXPECTED_U64: [u64; 65] = [
    0x907A56DE22C26E53, 0x7EAB43AAC7CDDD78, 0xB8D0569AB0B53D62,
    0x5C6BEFAB8A463D80, 0xF205A46893007EDA, 0x2B8A1668E4A94541,
    0xBD4CCC325BEFCA6F, 0x4D02AE1738F59482, 0xE1205108E55F3171,
    0x32D2644EC77A1584, 0xF6E10ACDB103A90B, 0xC3BBF4615B415C15,
    0x243CC2040063FA9C, 0xA89A58CE65E641FF, 0x24B031A348455A23,
    0x40793F86A449F33B, 0xCFAB3489F97EB832, 0x19FE67D2C8C5C0E2,
    0x04DD90A69C565CC2, 0x75D9518E2371C504, 0x38AD9B1141D3DD16,
    0x0264432CCD8A70E0, 0xA9DB5A6288683390, 0xD7B05492003F028C,
    0x205F615AEA59E51E, 0xEEE0C89621052884, 0x1BFC1A93A7284F4F,
    0x512175B5B70DA91D, 0xF71F8976A0A2C639, 0xAE093FEF1F84E3E7,
    0x22CA92B01161860F, 0x9FC7007CCF035A68, 0xA0C964D9ECD580FC,
    0x2C90F73CA03181FC, 0x185CF84E5691EB9E, 0x4FC1F5EF2752AA9B,
    0xF5B7391A5E0A33EB, 0xB9B84B83B4E96C9C, 0x5E42FE712A5CD9B4,
    0xA150F2F90C3F97DC, 0x7FA522D75E2D637D, 0x181AD0CC0DFFD32B,
    0x3889ED981E854028, 0xFB4297E8C586EE2D, 0x6D064A45BB28059C,
    0x90563609B3EC860C, 0x7AA4FCE94097C666, 0x1326BAC06B911E08,
    0xB926168D2B154F34, 0x9919848945B1948D, 0xA2A98FC534825EBE,
    0xE9809095213EF0B6, 0x582E5483707BC0E9, 0x086E9414A88A6AF5,
    0xEE86B98D20F6743D, 0xF89B7FF609B1C0A7, 0x4C7D9CC19E22C3E8,
    0x9A97005024562A6F, 0x5DD41CF423E6EBEF, 0xDF13609C0468E227,
    0x6E0DA4F64188155A, 0xB755BA4B50D7D4A1, 0x887A3484647479BD,
    0xAB8EEBE9BF2139A0, 0x75542C5D4CD2A6FF
];

#[test]
fn test_zero_arrays_64() {
    let data = [0; 65];
    for i in 0..data.len(){
        assert_eq!(highway_hash_64(&data[0..i], TEST_KEY_1), EXPECTED_U64[i]);
        exit(0)
    }
}

#[test]
fn test_trivial_arrays_64() {
    let data = {
        let mut data = [0; 65];
        for i in 0..33 {
            data[i] = 128 + (i as u8);
        }
        data
    };
    assert_eq!(highway_hash_64(&data[..33], TEST_KEY_2), 0x53c516cce478cad7);
}

const EXPECTED_U128: [u128; 65] = [
    0x36ad22224fae9fd3f2011b5b21e8d811,
    0xd63eb211a1fde2ab46560bdd6815195f,
    0x8a24866a9500257999e264be0dcdd494,
    0x7ddcd1288aadb0a7d1d16b251d2077ec,
    0x8254dbb3bfa92da6c9f97e3ad6ed50b5,
    0x56ae3b4481ac8909caa747e977c02d37,
    0xc28a19cf90029d86cc465ae4165ddb55,
    0xc2f41b553b560ec75f174701b7df45cb,
    0xa4160bc689565741e6c57739dd76e1a,
    0x4936bce1dcf8f7109b5ab6f77b9a878f,
    0x993292c7a00503b7eaeb59c837ac1106,
    0x388b3e0a7e4823c471e2fcdd08d5af2c,
    0x5e693bc78237f191819d24bad3e2d9fb,
    0xf80c0f7c8cc995a42d274c6e454e4dad,
    0xe4c3440fb75c1d806d734affbe9f5dbf,
    0x2d89650fe87021d2857ee5e66409ec2e,
    0x90aac7cfc3c6b007b7c9a5fdf5c6573,
    0x7ed7308c9577ade63c61aeb55cada8b,
    0xadc93b91a2be7bdba807c9d37d241e70,
    0x594f20048e7b28cbf4f603ea877625e5,
    0x9d4f422fb1af04c259968a242b5824ca,
    0x205f5d5494f5b4b390d9fd753db190bc,
    0x7a80057470430320d45e234dee66b5f8,
    0xbcf25e5b41f192479817e917bc0522cd,
    0xbd65882fd72ac7f8184c52cf8f06e6,
    0x1bd6c39012df295d9b07dc7abcac71be,
    0xa47bc9e4c1a3d90461b93dfedcedd64f,
    0x9aac5d2d3e71479a8f2b39ad0420230b,
    0x3252612affebdc03c46e29156ffda55,
    0x2c21c3d7404df285ff30899e1ab581,
    0x5f8081f3cbd97f6b789fb91386244d29,
    0x1c4957a1987f3d91f81d9b3cb9bd3e7c,
    0x880fe4cb4bf1073a6ef8df841b737cf3,
    0x647ec0cf4444e9666413c20432818dda,
    0x4fa6e96a0a505b1abb2150dff659655d,
    0x4ccc711bcff39ae9ce65c3584faf6f99,
    0xed3efb205805fd16d2cd758b2cf61775,
    0xb7adc6774eaa8c464f192ecb7ccd5261,
    0xda755cc123169b48767bce4224f0019c,
    0x5533259161f24553b946214c4502a62f,
    0x3d3e64de5d7ff542f09ff6dd7f08ca8,
    0x294ef97b4cdb710b5406c07b5fdf47ad,
    0x441ab97b6cded439d8f679320d45236,
    0xb00b486f1be8587357e19c74ef226ee1,
    0xbf612938f23ad1132d57421f3e1f5888,
    0xe70ca4da087a47ea7b44b76d79b45bc,
    0x7f3aa9b9f92393b8c22c09f8628fdd5a,
    0xc16b5cffaceb70d58ffdc90a6f198a6a,
    0x4c62219f8c5e3938169b3604db1dad79,
    0x649a95b88ad0435d769efe1d8b67176b,
    0xd9f097b065d60cda3b4808758d40c32f,
    0xdbec4ff6f9b6089d84da9633359da6dc,
    0xeb624a05b3b85b108d282b6fb6cd82f3,
    0x5910570531f9fbd27922271de292be49,
    0xe1f2f53d2a97c2b52af1572a61fc9c4,
    0xbd56ca3506aa1152dee4f5aea2a771d4,
    0x26fceb0717a498eb91d0651a0b7eeb0b,
    0x1ee974cf91121dc84f1e92c6300fd815,
    0x8010077fceef900c6939260acc108523,
    0x386a5a8625e653a54ac946075002fcdd,
    0x7b0d7fb7bb25ac2b5e74dfa91df2e77c,
    0x5c39157e391caf01daf2c21b288f7061,
    0xdfbc2c8d4409183be5e61f6072c14928,
    0x8c80a73314e9ab8e41edd56e05231ef1,
    0x3ccf28639615e4b7d59a5a5971109fb6
];

#[test]
fn test_zero_arrays_128() {
    let data = [0; 65];
    for i in 0..data.len(){
        assert_eq!(highway_hash_128(&data[0..i], TEST_KEY_1), EXPECTED_U128[i]);
        exit(0)
    }
}

#[test]
fn test_trivial_arrays_128() {
    let data = {
        let mut data = [0; 65];
        for i in 0..33 {
            data[i] = 128 + (i as u8);
        }
        data
    };
    assert_eq!(highway_hash_128(&data[..33], TEST_KEY_2), 0xc28ee99b5fe30297c034d1c68a51403f);
}