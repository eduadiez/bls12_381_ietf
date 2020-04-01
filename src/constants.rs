use lazy_static::lazy_static;
use num_bigint::BigUint;
use pairing::bls12_381::{Fq, Fq2};
use pairing::ff::{Field, PrimeField};
use std::string::String;

lazy_static! {

    pub static ref FQ_0: Fq = Fq::zero();
    pub static ref FQ_1: Fq = Fq::one();
    pub static ref FQ_2: Fq = Fq::from_str("2").unwrap();
    pub static ref FQ_12: Fq = Fq::from_str("12").unwrap();
    pub static ref FQ_18: Fq = Fq::from_str("18").unwrap();
    pub static ref FQ_240: Fq = Fq::from_str("240").unwrap();
    pub static ref FQ_1012: Fq = Fq::from_str("1012").unwrap();

    pub static ref FQ_INV_2: Fq = {
        let mut tmp = *FQ_2;
        tmp.negate();
        tmp
    };

    pub static ref FQ_INV_1: Fq = {
        let mut tmp = *FQ_1;
        tmp.negate();
        tmp
    };

    #[derive(Copy, Clone, Debug)]
    pub static ref ISO_3_A: Fq2 = Fq2 {
        c0: *FQ_0,
        c1: *FQ_240,
    };

    pub static ref ISO_3_B: Fq2 = Fq2 {
        c0: *FQ_1012,
        c1: *FQ_1012,
    };

    #[derive(Copy, Clone, Debug)]
    pub static ref ISO_3_Z: Fq2 = Fq2 {
            c0: *FQ_INV_2,
            c1: *FQ_INV_1,
    };

    // BigInt("1001205140483106588246484290269935788605945006208159541241399033561623546780709821462541004956387089373434649096260670658193992783731681621012512651314777238193313314641988297376025498093520728838658813979860931248214124593092835").toString(16).match(/.{16}/g).reverse().join(",0x")
    #[derive(Copy, Clone, Debug)]
    pub static ref P_MINUS_9_DIV_16: [u64; 12] = [
        0xb26a_a000_01c7_18e3,
        0xd7ce_d6b1_d763_82ea,
        0x3162_c338_3621_13cf,
        0x966b_f91e_d3e7_1b74,
        0xb292_e85a_8709_1a04,
        0x11d6_8619_c861_85c7,
        0xef53_1493_3097_8ef0,
        0x050a_62cf_d16d_dca6,
        0x466e_59e4_9349_e8bd,
        0x9e2d_c90e_50e7_046b,
        0x74bd_278e_aa22_f25e,
        0x002a_437a_4b8c_35fc,
    ];

    #[derive(Copy, Clone, Debug)]
    pub static ref RV1: Fq = Fq::from_str("1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257").unwrap();
    #[derive(Copy, Clone, Debug)]
    pub static ref RV1_NEGATE: Fq = {
        let mut rv1_negate: Fq = *RV1;
        rv1_negate.negate();
        rv1_negate
    };

    #[derive(Copy, Clone, Debug)]
    pub static ref POSITIVE_EIGTH_ROOTS_OF_UNITY: [Fq2; 4] = [
        Fq2 {
            c0: *FQ_1,
            c1: *FQ_0,
        },
        Fq2 {
            c0: *FQ_0,
            c1: *FQ_1,
        },
        Fq2 {
            c0: *RV1,
            c1: *RV1
        },
        Fq2 {
            c0: *RV1,
            c1: *RV1_NEGATE,
        },
    ];

    // EV1 = 1015919005498129635886032702454337503112659152043614931979881174103627376789972962005013361970813319613593700736144
    // EV2 = 1244231661155348484223428017511856347821538750986231559855759541903146219579071812422210818684355842447591283616181
    // EV3 = 1646015993121829755895883253076789309308090876275172350194834453434199515639474951814226234213676147507404483718679
    // EV4 = 1637752706019426886789797193293828301565549384974986623510918743054325021588194075665960171838131772227885159387073

    #[derive(Copy, Clone, Debug)]
    pub static ref EV1: Fq = Fq::from_str("1015919005498129635886032702454337503112659152043614931979881174103627376789972962005013361970813319613593700736144").unwrap();
    #[derive(Copy, Clone, Debug)]
    pub static ref EV2: Fq = Fq::from_str("1244231661155348484223428017511856347821538750986231559855759541903146219579071812422210818684355842447591283616181").unwrap();
    #[derive(Copy, Clone, Debug)]
    pub static ref EV3: Fq = Fq::from_str("1646015993121829755895883253076789309308090876275172350194834453434199515639474951814226234213676147507404483718679").unwrap();
    #[derive(Copy, Clone, Debug)]
    pub static ref EV4: Fq = Fq::from_str("1637752706019426886789797193293828301565549384974986623510918743054325021588194075665960171838131772227885159387073").unwrap();
    #[derive(Copy, Clone, Debug)]
    pub static ref EV2_NEG: Fq = {
        let mut tmp: Fq = *EV2;
        tmp.negate();
        tmp
    };
    #[derive(Copy, Clone, Debug)]
    pub static ref EV4_NEG: Fq = {
        let mut tmp: Fq = *EV4;
        tmp.negate();
        tmp
    };
    #[derive(Copy, Clone, Debug)]
    pub static ref ETAS: [Fq2; 4] = [
        Fq2 {
            c0: *EV1,
            c1: *EV2
        },
        Fq2 {
            c0: *EV2_NEG,
            c1: *EV1,
        },
        Fq2 {
            c0: *EV3,
            c1: *EV4
        },
        Fq2 {
            c0: *EV4_NEG,
            c1: *EV3,
        },
    ];

    pub static ref ISO_3_K_1_0_VAL: String = String::from("889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235542");
    pub static ref ISO_3_K_1_0_FQ: Fq = Fq::from_str(&ISO_3_K_1_0_VAL).expect("Error getting Fq from str");

    pub static ref ISO_3_K_1_0: Fq2 = Fq2 {
        c0: *ISO_3_K_1_0_FQ,
        c1: *ISO_3_K_1_0_FQ,
    };

    pub static ref ISO_3_K_1_1: Fq2 = Fq2 {
        c0: *FQ_0,
        c1: Fq::from_str("2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706522").expect("Error getting Fq from str")
    };
    pub static ref ISO_3_K_1_2: Fq2 = Fq2 {
        c0: Fq::from_str("2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706526").expect("Error getting Fq from str"),
        c1: Fq::from_str("1334136518407222464472596608578634718852294273313002628444019378708010550163612621480895876376338554679298090853261").expect("Error getting Fq from str")
    };
    pub static ref ISO_3_K_1_3: Fq2 = Fq2 {
        c0: Fq::from_str("3557697382419259905260257622876359250272784728834673675850718343221361467102966990615722337003569479144794908942033").expect("Error getting Fq from str"),
        c1: *FQ_0
    };
    pub static ref ISO_3_X_NUMERATOR: [Fq2;4]  = [
        *ISO_3_K_1_0,
        *ISO_3_K_1_1,
        *ISO_3_K_1_2,
        *ISO_3_K_1_3
    ];
    pub static ref ISO_3_K_2_0: Fq2 = Fq2 {
        c0: *FQ_0 ,
        c1: Fq::from_str("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559715").expect("Error getting Fq from str")
    };
    pub static ref ISO_3_K_2_1: Fq2 = Fq2 {
        c0: *FQ_12,
        c1: Fq::from_str("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559775").expect("Error getting Fq from str")
    };
    pub static ref ISO_3_K_2_2: Fq2 = Fq2::one();
    pub static ref ISO_3_K_2_3: Fq2 = Fq2::zero();
    pub static ref ISO_3_X_DENOMINATOR: [Fq2;4] = [
        *ISO_3_K_2_0,
        *ISO_3_K_2_1,
        *ISO_3_K_2_2,
        *ISO_3_K_2_3
    ];

    // Y Numerator
    pub static ref ISO_3_K_3_0_VAL: String = String::from("3261222600550988246488569487636662646083386001431784202863158481286248011511053074731078808919938689216061999863558");
    pub static ref ISO_3_K_3_0_FQ: Fq = Fq::from_str(&ISO_3_K_3_0_VAL).expect("Error getting Fq from str");
    pub static ref ISO_3_K_3_0: Fq2 = Fq2 {
        c0: *ISO_3_K_3_0_FQ,
        c1: *ISO_3_K_3_0_FQ,
    };

    pub static ref ISO_3_K_3_1: Fq2 = Fq2 {
        c0: *FQ_0,
        c1: Fq::from_str("889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235518").expect("Error getting Fq from str")
    };
    pub static ref ISO_3_K_3_2: Fq2 = Fq2 {
        c0: Fq::from_str("2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706524").expect("Error getting Fq from str"),
        c1: Fq::from_str("1334136518407222464472596608578634718852294273313002628444019378708010550163612621480895876376338554679298090853263").expect("Error getting Fq from str")
    };
    pub static ref ISO_3_K_3_3: Fq2 = Fq2 {
        c0: Fq::from_str("2816510427748580758331037284777117739799287910327449993381818688383577828123182200904113516794492504322962636245776").expect("Error getting Fq from str"),
        c1: *FQ_0
    };
    pub static ref ISO_3_Y_NUMERATOR: [Fq2;4] = [
        *ISO_3_K_3_0,
        *ISO_3_K_3_1,
        *ISO_3_K_3_2,
        *ISO_3_K_3_3
    ];

    // Y Denominator
    pub static ref ISO_3_K_4_0_VAL: String = String::from("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559355");
    pub static ref ISO_3_K_4_0_FQ: Fq = Fq::from_str(&ISO_3_K_4_0_VAL).expect("Error getting Fq from str");
    pub static ref ISO_3_K_4_0: Fq2 = Fq2 {
        c0: *ISO_3_K_4_0_FQ,
        c1: *ISO_3_K_4_0_FQ,
    };

    pub static ref ISO_3_K_4_1: Fq2 = Fq2 {
        c0: *FQ_0 ,
        c1: Fq::from_str("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559571").expect("Error getting Fq from str")
    };
    pub static ref ISO_3_K_4_2: Fq2 = Fq2 {
        c0: *FQ_18,
        c1: Fq::from_str("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559769").expect("Error getting Fq from str")
    };
    pub static ref ISO_3_K_4_3: Fq2 = Fq2::one();
    pub static ref ISO_3_Y_DENOMINATOR: [Fq2;4] = [
        *ISO_3_K_4_0,
        *ISO_3_K_4_1,
        *ISO_3_K_4_2,
        *ISO_3_K_4_3
    ];

    pub static ref ISO_3_MAP_COEFFICIENTS: [[Fq2;4];4] = [
        *ISO_3_X_NUMERATOR,
        *ISO_3_X_DENOMINATOR,
        *ISO_3_Y_NUMERATOR,
        *ISO_3_Y_DENOMINATOR,
    ];

    // h_eff from https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-8.9.2
    // "209869847837335686905080341498658477663839067235703451875306851526599783796572738804459333109033834234622528588876978987822447936461846631641690358257586228683615991308971558879306463436166481";
    // "0bc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551"
    #[derive(Copy, Clone, Debug)]
    pub static ref H_EFF: BigUint = {
        let mut buf = [0u8; 80];
        hex::decode_to_slice("0bc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551", &mut buf as &mut [u8]).expect("Error usign hex::decode_to_slice");
        BigUint::from_bytes_be(&buf)
    };
}
