import init, { js_get_collateral, js_verify } from "./dcap-qvl-web.js";

export const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;
export const STATEMENT_PURPOSE = "aci.report_data.v1";
export const MVP_E2EE_ALGO = "pa-mvp-x25519-aes256gcm-v1";
const MVP_HKDF_INFO = "pa-mvp/e2ee/v1";

export const KNOWN_PROD_IMAGES = {
  "dstack-0.6.1": {
    os_image_hash: "ec43cb8c5e04b6bb6c53b33b16076a01d83d01f7f4b703f2f78a0d947d6247e6",
    mrtd: ["2a674327c50218dba880066b349b8d559d749ed68dce33fd651c184a877d084b07a9e583767a7ad5da13ed91deec2b70",
           "83baf004a06c83f6371d4d9e19c8bb1ead734ba7696e56d6b52271011394a6f24efecc27af3b5c1da41594dbfa706e97"],
    rtmr1: "89ef86c5125b986c325f0a94acfa87718a4ef3a4d4f237dbb72dda3cf777fd2c054555fb4407eb53338d7d67329a7333",
    rtmr2: "e9000e338f33233e8f51b7fd031e1c158bdcf8572eab041c0bc8eb7fef48b23259a6a556e6c8e2af99999fc39c793179",
  },
  "dstack-0.5.12": {
    os_image_hash: "8db40cb23008d6213668b5816702d100b37b859a8a5bfd18d938ae3a1b3715bd",
    mrtd: ["7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173",
           "df4d77c857de652bd0fafa343a2026b51071ee03773d076d283abf1a7d36ff91ffa279ee4a617ac664f7e2a2c8d5891b"],
    rtmr1: "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec",
    rtmr2: "764489f277a8540189761e72b4238ba36d4d647e11bd958d8ab5522af2a4867b0ff63e06b0c4967f1857236244040a5d",
  },
  "dstack-0.5.9": {
    os_image_hash: "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033",
    mrtd: ["f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
           "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217"],
    rtmr1: "07e6f51aa763abfe75c3ddfbf4f425fe3f0ceff66d807a75e049303dce9addf68e7218729bd419638af63a370f65878c",
    rtmr2: "df67e467e60edc1737bcf8e682d48131bfb427f523226aa7f197a7608e9b3784783fa759ef5b28191fa12f9ddb36b858",
  },
};
export const KNOWN_RTMR0 = {
  "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96":
    "1 vCPU / 2 GB（Phala tdx.small，QEMU 8.2.2）",
  "027b610ab0555482f8a3868524093bdf3cdbe2539f81dfeeb886864654cb2fe3422f7fc36d4bab6fa46683aad11d1ba7":
    "2 vCPU / 4 GB（Phala tdx.medium，QEMU 8.2.2）",
  "46a83f6bbbeaa274aaf04861ef47d7e8898d4e699126b642f72f582e8d7f5349cb266a188bbabf619940d4fece06594b":
    "32 vCPU / 32 GB（Phala 推理网关，QEMU 8.2.2）",
};
const LOGIN_ENVS = ["DSTACK_AUTHORIZED_KEYS", "DSTACK_ROOT_PASSWORD", "DSTACK_ROOT_PUBLIC_KEY"];
const TCB_PASS = new Set(["UpToDate", "SWHardeningNeeded"]);
const TCB_WARN = new Set(["ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded", "OutOfDate", "OutOfDateConfigurationNeeded"]);
const HEX64 = /^[0-9a-f]{64}$/;
export const GATEWAY_HOST = "inference.phala.com";
const COLLATERAL_TTL_MS = 10 * 60 * 1000;
const TCB_LOCAL = "LocalDev";
export const SESSION_TTL = 15 * 60;

export const NEAR_PINS = {
  "image": "dstack-nvidia-0.5.12",
  "observed": "2026-10-28、2026-11-04",
  "mrtd": ["7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173", "df4d77c857de652bd0fafa343a2026b51071ee03773d076d283abf1a7d36ff91ffa279ee4a617ac664f7e2a2c8d5891b"],
  "rtmr0": ["bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590", "f0f303d15fb7619b87ec60daf0db241e937b30a4e1f2c405b5420f14b27c6e301735094feea9693a33b868d00eeb07f9"],
  "rtmr1": "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec",
  "rtmr2": "bd67ab7554dc27ab03a077bc1447a1a67d0624ff547c4c809a8626f12d6a89712f8ec60e781e99b98208574065d21a71",
  "os_image_hash": "91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829",
  "kms": "3059301306072a8648ce3d020106082a8648ce3d03010703420004394aaed2c745e6a457cb835f7f47423f57ff3ead71b92abff6bdc14d905b319f2e13961b42c50740dae4498d9c51dd7a2e227660c9e5c504083cda06b6c11682",
  "app_ids": ["2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b"],
  "compose_hashes": ["5e513dbd72e1c0f291f748ad06d4dbc1df55659869e649376213ac7b3c9d2e29", "31d3b2389e06a4450e342f3a45fdbb5d7ce4c607c359f5b291635548b0b80007"],
};

export const CHUTES_PINS = {
  "source": "https://api.chutes.ai/servers/tee/measurements",
  "fetched": "2026-10-28",
  "images": {
    "1.3.1": {"mrtd": "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d", "rtmr1": "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207", "rtmr2": "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968", "rtmr3": "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"},
    "1.4.0": {"mrtd": "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d", "rtmr1": "d3a862ff47357f374fc72c7f02a480a13790d1805e24aaa8de1f03994256625ce0f593ae35ea8f0c24d09f7df36cb0ed", "rtmr2": "8feee49b83c0f912f9ab9366a7423f65417bb60223c1871a5d55e84d92d741c80017b3f856317c45295255db70f8dc3e", "rtmr3": "7e7adbc834a3e746278f28c607a94ba93407a7b25055daca4836cc6003e9bfb5f48836fa0e1d6ab6637c187dd142e5f6"},
    "1.4.1": {"mrtd": "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d", "rtmr1": "d3a862ff47357f374fc72c7f02a480a13790d1805e24aaa8de1f03994256625ce0f593ae35ea8f0c24d09f7df36cb0ed", "rtmr2": "da23f73e0fddeb8128f706ecfbecbcf8cee34af7e4907d8fbc85e9b216acee27bf6cc3655eaf4d33cab76adea79fa153", "rtmr3": "d9dc4c6079fb12a21ad2aa8e329d8bfa61aaa13d3ffd10a93a2c4e82f0e35efbf28f5cf3bed0c0c1b517a7c327a25226"},
    "1.5.0": {"mrtd": "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d", "rtmr1": "d3a862ff47357f374fc72c7f02a480a13790d1805e24aaa8de1f03994256625ce0f593ae35ea8f0c24d09f7df36cb0ed", "rtmr2": "e1de99043052f3e1ab5a4463d3310b5680e851631adf10e071b15cbd8b4d664ea435b0ec33e7f18e908dda60734056f7", "rtmr3": "9617be835beac8c62093a9db424f015f3e12651235d0101c112729e7225b7a70836a184dee0b45f28cd190f1871afe6e"}
  },
  "rows": [
    ["1.3.1", "8xh200 [10.2.1]", "212d8284fe29a52a033cd662763e452915d2002bcc3c3e73aa660b100087bd3cce8aef414c3d7012f6a857f392c1919b", ["h200"], 8],
    ["1.3.1", "8xh200 [10.2.1, NVSW0]", "c90a27d633d97e2f785a0a65c4a7ee2258872655e3bada2cad0e719e313db542fd35c6889897d9ae6369f82e39877861", ["h200"], 8],
    ["1.3.1", "8xh200 [10.2.1, FLAT]", "b237753a1c8a05042209947fc0f98c8459783db7f3411860c38249c5abd4efd8c6fb7820036ff19b5099138aaf9e0bd1", ["h200"], 8],
    ["1.3.1", "8xh200 [10.1.0]", "7e76988fae31dda82f0043b331d908f0716e9da24fed80b6ea6cec9b6615ff84f24321056a8befbea3fff67bd1e59205", ["h200"], 8],
    ["1.3.1", "8xh200 [10.1.0, NVSW0]", "cdf7169a9f90c4d2fd29f89579f4ad7b90c272d607bc7ba2365e91560a248b9eafe01940f3c1e9d6bd6987573080b6c1", ["h200"], 8],
    ["1.3.1", "8xh200 [10.1.0-flat]", "ed373dfcc4e3b9cc57282773784c88445699f95705ec0995959c4aa95f9dec454c76da891fa56f820f547b02db8c1f2f", ["h200"], 8],
    ["1.3.1", "8xRTX_PRO_6000 [10.1.0]", "0917443cc41e9a5afebc8e87e69a63f32208c47d4b4b4fd410fbc1a705e1880c1383a4ad51903a5ed20cb4090420185a", ["pro_6000"], 8],
    ["1.3.1", "8xRTX_PRO_6000 [10.2.1, NUMA2-4/4]", "5fc09d108ef74d5505b876690de5ab5da02af463ba84bb33299efd1c02144b5d7a6ba579b3ff31ef9118350468e9faf2", ["pro_6000"], 8],
    ["1.3.1", "8xRTX_PRO_6000 [10.2.1, NUMA2-3/5]", "1de32a41a8116e042f33e9cb813f1f6edfef1452c8b2cf54df5451a848ef8931e97f40927191acabfd111c8b8d66796a", ["pro_6000"], 8],
    ["1.3.1", "8xRTX_PRO_6000 [10.2.1, FLAT]", "e9f0b31ce30e4917767d22ad26ad0a8f4edc095b8d9f4bbb36c9cc24fe274aa2dfe16ce3c961dac2d8cef3e6ae2e901d", ["pro_6000"], 8],
    ["1.3.1", "8xRTX_PRO_6000 [10.2.1, FLAT, MSI-GNR]", "872d965083f0bab7d080bd7d40155ba1b2b911d883f391ab7d6b9d810abeefd058e04129d72c088cf4fd05c099a57704", ["pro_6000"], 8],
    ["1.3.1", "8xb200 [10.2.1]", "35038cbb04f872ac6d2784b05c912c438007583e58960dc66fb02d1b04462dd5994f94536da37b5877ccd3dd27d8d54d", ["b200"], 8],
    ["1.3.1", "8xb200 [10.2.1, IB4]", "555fc635cd49723dc33d53a9d53be82fd161be351174e5449a465bbeffbcbd01f36d89dcd25fad61bf4c9e65c570f5d6", ["b200"], 8],
    ["1.3.1", "8xb200 [10.2.1, XEON6]", "65fd972e40ac4d8a933d10ebfc31f07336cf1e45a3864523427b454df5d3b9dd0043f10e975da39677b62d45860c13e3", ["b200"], 8],
    ["1.3.1", "8xb200 [10.2.1, XEON6, 272CPU]", "9673907ceb0c9ca79337437bb91695e7a3d19e82df1e41de1b0d2db8081fccb5d82f26d479a5016553cb20964d5948b9", ["b200"], 8],
    ["1.3.1", "8xb200 [10.2.1, XEON6, SNC3]", "ccef43242ef633a542405dbfe55d04d823a50586b0a07510d058ea88ad8d1f8281f227f00c664435d92b23431c4d1c3c", ["b200"], 8],
    ["1.3.1", "8xb200 [10.2.1, ubuntu3]", "ff42d0f7b03cbe84f9e252d8f912b465852c8ee92584c5c047de134a46c8f1e1545683e713bbdd64e2af7d10e8bafaae", ["b200"], 8],
    ["1.3.1", "8xb300", "91adf9667ba4c65bec5345a8c9b98010708d903847bf838c4526c3ebbc35561719e2127e48a3f6f77f651d71d2cbc8d4", ["b300"], 8],
    ["1.3.1", "8xb300 [10.2.1, numa-256c]", "f24aaec75a6c8783222ab141f003f2180fce573ef9cc6ea3dcdc2fcb91c051650fcd74ec85f02e367f06ed71328d319b", ["b300"], 8],
    ["1.4.0", "8xb300 [10.2.1, flat-252c-1944g]", "fc71a5a8edcb1f6d307d59e62ce257365df0f233ae2334691f99d2136832d911f8be975b92f88036db8a4906574519c4", ["b300"], 8],
    ["1.4.0", "8xh200 [10.2.1, flat-188c-1128g-nvsw4]", "b72208e4b39593a82bbdbc394569bd6f8395f76bdcff5bce2bc72f4e2ca0b3202238d3b78952b497d725e04999e45435", ["h200"], 8],
    ["1.4.0", "8xh200 [10.2.1, numa-124c-1128g-nvsw-node1]", "5b509103a3bf3c10dbf27a7da030a3d7ba93a81c0c8844de20e5dfee77611644a39cc7236313e9d0a99a8a8a703bbfc9", ["h200"], 8],
    ["1.4.0", "8xb300 [10.2.1, numa-252c-2304g]", "b60b5c5817c762e3297ccec4e6a49289781fc5511738230bbc88e253e120635526b6082f8f4f6c31a2b3821d30a8b221", ["b300"], 8],
    ["1.4.0", "8xpro_6000 [10.2.1, numa-124c-768g]", "5e939a6213a6751f162617c6e9a50461786b3f9a6a679ebf7706fa705e7934180825b2fae43a60877ea9117a1e4d4f60", ["pro_6000"], 8],
    ["1.4.1", "8xb300 [10.2.1, flat-252c-1944g]", "fc71a5a8edcb1f6d307d59e62ce257365df0f233ae2334691f99d2136832d911f8be975b92f88036db8a4906574519c4", ["b300"], 8],
    ["1.4.1", "8xh200 [10.2.1, numa-236c-1128g-nvsw-node1]", "a9cac743d296a96c7a0d6348f03be1e1a407f18ec215f0039e3dc1ea4c132eb1e4a5fe3783022ff3d252d4b30f1dbf9f", ["h200"], 8],
    ["1.4.1", "8xh200 [10.2.1, numa-188c-1128g-nvsw-node0]", "052183ad6cca5ad4aef7e31dc3f6c47be2ba90c288a55420bf432301374f1bd9932ea7d6b5da999c4fecf578c4b0a21a", ["h200"], 8],
    ["1.4.1", "8xh200 [10.2.1, flat-188c-1128g-nvsw4]", "b72208e4b39593a82bbdbc394569bd6f8395f76bdcff5bce2bc72f4e2ca0b3202238d3b78952b497d725e04999e45435", ["h200"], 8],
    ["1.4.1", "8xh200 [10.2.1, flat-188c-1128g-nvsw4]", "b72208e4b39593a82bbdbc394569bd6f8395f76bdcff5bce2bc72f4e2ca0b3202238d3b78952b497d725e04999e45435", ["h200"], 8],
    ["1.4.1", "8xh200 [10.2.1, numa-124c-1128g-nvsw-node1]", "5b509103a3bf3c10dbf27a7da030a3d7ba93a81c0c8844de20e5dfee77611644a39cc7236313e9d0a99a8a8a703bbfc9", ["h200"], 8],
    ["1.4.1", "8xpro_6000 [10.2.1, flat-188c-768g]", "0e53740f96063640ec986e9f95a2cb601bd686c34229882a05fe7a4350d78735fc3dc2439b6052665ef888e38a292076", ["pro_6000"], 8],
    ["1.4.1", "8xpro_6000 [10.2.1, numa-124c-768g] (58443435b208)", "bacb4abf7b19aba4a8307ebc7244706745de4fa627e669e7f06fd35c3303eea1903f58dc143d27b557da1a986e0e95f6", ["pro_6000"], 8],
    ["1.4.1", "8xh200 [10.2.1, numa-188c-1128g-nvsw-node1]", "ba81dbf034d968fd4be0975c031cbe6451295d63cb509cd857372fc915dada1b24fc4e1b0486db4a276a9efb49d415e6", ["h200"], 8],
    ["1.4.1", "8xh200 [10.2.1, numa-188c-987g]", "8bf87f63caf5265365315fcdeea36e791c6d16216898aa313a1f4ac6fb0181adef223b2b62ad94914b06e0066ceb4751", ["h200"], 7],
    ["1.4.1", "8xb200 [10.2.1, flat-272c-1536g]", "44efeea3a647090c2969cca7f29963dde696d99542c28536a20ad3586a639ef7e230d8d4e325c55f3597dc7b58b30903", ["b200"], 8],
    ["1.4.1", "8xb300 [10.2.1, numa-flatpci-252c-2304g]", "e861504d4a05ba1e949618ef759d6fbf0c69e4774b667e9fb876b664cb1bb70e3094d2cddc9ac6c52d4b5d352ba2e1d3", ["b300"], 8],
    ["1.4.1", "8xpro_6000 [10.2.1, numa-124c-768g] (f2ab1d61fa64)", "5e939a6213a6751f162617c6e9a50461786b3f9a6a679ebf7706fa705e7934180825b2fae43a60877ea9117a1e4d4f60", ["pro_6000"], 8],
    ["1.4.1", "8xb300 [10.2.1, flat-188c-2304g]", "bfaaf9a018fb3f10518b2706731ed010bc7d75f3ea3eabcc562ce4a794ab4ee88eba199e38f9013e96e1099a1cf7c49e", ["b300"], 8],
    ["1.4.1", "8xb300 [10.2.1, numa-flatpci-188c-2304g]", "34c932b17fa65b230d848ad0ca6b8186dc347b129f926f968f6b607dae07e1968177684d209a1830d37b5d0486c97618", ["b300"], 8],
    ["1.4.1", "8xpro_6000 [10.2.1, numa-204c-768g]", "a5488b5f4cf1484da23001e013a5ad3ff177836bf2cfdbde55dacded21b3eece5de43d4c4a2d5279f8ed8d24b9e072d6", ["pro_6000"], 8],
    ["1.5.0", "8xb300 [10.2.1, flat-252c-1944g]", "fc71a5a8edcb1f6d307d59e62ce257365df0f233ae2334691f99d2136832d911f8be975b92f88036db8a4906574519c4", ["b300"], 8],
    ["1.5.0", "8xh200 [10.2.1, flat-188c-1128g-nvsw4]", "b72208e4b39593a82bbdbc394569bd6f8395f76bdcff5bce2bc72f4e2ca0b3202238d3b78952b497d725e04999e45435", ["h200"], 8],
    ["1.5.0", "8xh200 [10.2.1, flat-188c-1128g-nvsw4]", "b72208e4b39593a82bbdbc394569bd6f8395f76bdcff5bce2bc72f4e2ca0b3202238d3b78952b497d725e04999e45435", ["h200"], 8],
    ["1.5.0", "8xh200 [10.2.1, numa-236c-1128g-nvsw-node1]", "a9cac743d296a96c7a0d6348f03be1e1a407f18ec215f0039e3dc1ea4c132eb1e4a5fe3783022ff3d252d4b30f1dbf9f", ["h200"], 8],
    ["1.5.0", "8xh200 [10.2.1, numa-188c-1128g-nvsw-node0]", "052183ad6cca5ad4aef7e31dc3f6c47be2ba90c288a55420bf432301374f1bd9932ea7d6b5da999c4fecf578c4b0a21a", ["h200"], 8],
    ["1.5.0", "8xb300 [10.2.1, numa-flatpci-188c-2304g]", "34c932b17fa65b230d848ad0ca6b8186dc347b129f926f968f6b607dae07e1968177684d209a1830d37b5d0486c97618", ["b300"], 8],
    ["1.5.0", "8xpro_6000 [10.2.1, flat-252c-768g] (2f9da10068f0)", "c2857dd69249c2f976ad070359b7bebc828c9d39a899bebc1fc9077072d97c6137f626b9ce7280fff0aa7e68481f16c6", ["pro_6000"], 8],
    ["1.5.0", "8xb300 [10.2.1, flat-188c-2304g]", "bfaaf9a018fb3f10518b2706731ed010bc7d75f3ea3eabcc562ce4a794ab4ee88eba199e38f9013e96e1099a1cf7c49e", ["b300"], 8],
    ["1.5.0", "8xh200 [10.2.1, numa-124c-1128g-nvsw-node1]", "5b509103a3bf3c10dbf27a7da030a3d7ba93a81c0c8844de20e5dfee77611644a39cc7236313e9d0a99a8a8a703bbfc9", ["h200"], 8],
    ["1.5.0", "8xpro_6000 [10.2.1, flat-188c-768g]", "0e53740f96063640ec986e9f95a2cb601bd686c34229882a05fe7a4350d78735fc3dc2439b6052665ef888e38a292076", ["pro_6000"], 8],
    ["1.5.0", "8xpro_6000 [10.2.1, numa-124c-768g] (58443435b208)", "bacb4abf7b19aba4a8307ebc7244706745de4fa627e669e7f06fd35c3303eea1903f58dc143d27b557da1a986e0e95f6", ["pro_6000"], 8],
    ["1.5.0", "8xh200 [10.2.1, numa-188c-1128g-nvsw-node1]", "ba81dbf034d968fd4be0975c031cbe6451295d63cb509cd857372fc915dada1b24fc4e1b0486db4a276a9efb49d415e6", ["h200"], 8],
    ["1.5.0", "8xh200 [10.2.1, numa-188c-987g]", "8bf87f63caf5265365315fcdeea36e791c6d16216898aa313a1f4ac6fb0181adef223b2b62ad94914b06e0066ceb4751", ["h200"], 7],
    ["1.5.0", "8xb200 [10.2.1, flat-272c-1536g]", "44efeea3a647090c2969cca7f29963dde696d99542c28536a20ad3586a639ef7e230d8d4e325c55f3597dc7b58b30903", ["b200"], 8],
    ["1.5.0", "8xb200 [10.2.1, flat-208c-1536g]", "0e990b232dc6df68c5208dac9eb23f777950b7b9ce638b8299dd44ba97902cbcc035c97b704cb28a23643771f8438cbc", ["b200"], 8],
    ["1.5.0", "8xb300 [10.2.1, numa-flatpci-252c-2304g]", "e861504d4a05ba1e949618ef759d6fbf0c69e4774b667e9fb876b664cb1bb70e3094d2cddc9ac6c52d4b5d352ba2e1d3", ["b300"], 8],
    ["1.5.0", "8xpro_6000 [10.2.1, numa-124c-768g] (f2ab1d61fa64)", "5e939a6213a6751f162617c6e9a50461786b3f9a6a679ebf7706fa705e7934180825b2fae43a60877ea9117a1e4d4f60", ["pro_6000"], 8],
    ["1.5.0", "8xpro_6000 [10.2.1, numa-204c-768g]", "a5488b5f4cf1484da23001e013a5ad3ff177836bf2cfdbde55dacded21b3eece5de43d4c4a2d5279f8ed8d24b9e072d6", ["pro_6000"], 8]
  ],
  "gpu_models": {"h200": ["GH100"], "b200": ["GB100"], "pro_6000": ["GB20X"]},
  "nras_intermediates": ["ba14d00377699189b6762c22c744a9dbdc62aa9396097ada7150426c6ff39afc", "fd32837f954e2c45db073105166dfe6985ae0480bb113fba63b091a75affe896"],
};

const enc = new TextEncoder();
const subtle = globalThis.crypto.subtle;

export function hexToBytes(h) {
  h = String(h || "");
  if (h.length % 2 || /[^0-9a-fA-F]/.test(h)) throw new Error(`不是十六进制：${h.slice(0, 20)}`);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function concat(...parts) {
  const bufs = parts.map((p) => (typeof p === "string" ? enc.encode(p) : p));
  const out = new Uint8Array(bufs.reduce((n, b) => n + b.length, 0));
  let o = 0;
  for (const b of bufs) { out.set(b, o); o += b.length; }
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export async function sha256(data) {
  return new Uint8Array(await subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data));
}

async function sha384(data) {
  return new Uint8Array(await subtle.digest("SHA-384", data));
}

export async function sha256Tag(data) {
  return "sha256:" + bytesToHex(await sha256(data));
}

export function randomHex(n = 32) {
  return bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(n)));
}

export function jcs(obj) {
  return enc.encode(canonical(obj));
}

function canonical(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error("JCS: 文档里有浮点数，本实现不支持");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
  }
  throw new Error(`JCS: 不支持的类型 ${typeof v}`);
}

export async function keysetDigest(keyset) {
  return sha256Tag(jcs(keyset));
}

export function statement(digest, nonceHex) {
  if (!/^sha256:[0-9a-f]{64}$/.test(digest)) throw new Error("公钥集摘要格式不对");
  let n;
  if (nonceHex === null || nonceHex === undefined) n = "null";
  else if (HEX64.test(nonceHex)) n = `"${nonceHex}"`;
  else throw new Error("nonce 必须是 64 位小写十六进制");
  return enc.encode(`{"keyset_digest":"${digest}","nonce":${n},"purpose":"${STATEMENT_PURPOSE}"}`);
}

export async function expectedReportData(digest, nonceHex) {
  return concat(await sha256(statement(digest, nonceHex)), new Uint8Array(32));
}

export function parseTdReport(quote) {
  if (quote.length < 48) throw new Error("quote 太短");
  const dv = new DataView(quote.buffer, quote.byteOffset, quote.byteLength);
  const version = dv.getUint16(0, true);
  const teeType = dv.getUint32(4, true);
  if (teeType !== 0x81) throw new Error(`不是 TDX quote（tee_type ${teeType}）`);
  let off;
  if (version === 4) off = 48;
  else if (version === 5) off = 54;
  else throw new Error(`不支持的 quote 版本 ${version}`);
  if (quote.length < off + 584) throw new Error("quote 太短");
  const f = (start, len) => quote.slice(off + start, off + start + len);
  return {
    version, tee_type: teeType, att_key_type: dv.getUint16(2, true), qe_vendor_id: quote.slice(12, 28),
    tee_tcb_svn: f(0, 16), mr_seam: f(16, 48), mr_signer_seam: f(64, 48), seam_attributes: f(112, 8),
    td_attributes: f(120, 8), xfam: f(128, 8), mr_td: f(136, 48), mr_config_id: f(184, 48),
    mr_owner: f(232, 48), mr_owner_config: f(280, 48),
    rt_mr0: f(328, 48), rt_mr1: f(376, 48), rt_mr2: f(424, 48), rt_mr3: f(472, 48),
    report_data: f(520, 64),
  };
}

export async function replayImr(events, imr) {
  let mr = new Uint8Array(48);
  const steps = [];
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (Number(e.imr) !== imr) continue;
    mr = await sha384(concat(mr, hexToBytes(e.digest || "")));
    steps.push({ index: i, rtmr: bytesToHex(mr) });
  }
  return { mr: bytesToHex(mr), steps };
}

export function parseEventLog(eventLog) {
  if (typeof eventLog === "string") eventLog = JSON.parse(eventLog);
  if (!Array.isArray(eventLog)) throw new Error("event_log 不是数组");
  return eventLog;
}

export function runtimeEventPreimage(e) {
  const payload = hexToBytes(e.event_payload || "");
  if (Number(e.version ?? 1) === 2) {
    return jcs({ name: e.event, payload: bytesToHex(payload), type: DSTACK_RUNTIME_EVENT_TYPE });
  }
  const t = new Uint8Array(4);
  new DataView(t.buffer).setUint32(0, DSTACK_RUNTIME_EVENT_TYPE, true);
  return concat(t, ":", e.event, ":", payload);
}

export async function replayRtmr3(events) {
  let mr = new Uint8Array(48);
  const named = {};
  const errors = [];
  const steps = [];
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (Number(e.imr) !== 3) continue;
    let digest = hexToBytes(e.digest || "");
    if (Number(e.event_type) !== DSTACK_RUNTIME_EVENT_TYPE) {
      errors.push(`第 ${i} 条事件不是 dstack 运行时事件，无法核对内容`);
    } else {
      const pre = runtimeEventPreimage(e);
      if (e.preimage && !bytesEqual(hexToBytes(e.preimage), pre)) {
        errors.push(`第 ${i} 条事件（${e.event}）的 preimage 不是规范形式`);
      }
      const h = await sha384(pre);
      if (!digest.length) digest = h;
      else if (!bytesEqual(h, digest)) errors.push(`第 ${i} 条事件（${e.event}）的摘要和内容对不上`);
      (named[e.event] ||= []).push(String(e.event_payload || "").toLowerCase());
    }
    mr = await sha384(concat(mr, digest));
    steps.push({ index: i, event: e.event, payload: String(e.event_payload || ""), digest: bytesToHex(digest), rtmr3: bytesToHex(mr) });
  }
  return { mr, named, errors, steps };
}

export function embeddedSource(composeText, marker = "PYEOF") {
  const lines = composeText.split("\n");
  const start = lines.findIndex((l) => l.trimEnd().endsWith(`<<'${marker}'`));
  if (start < 0) return null;
  let end = -1;
  for (let i = start + 1; i < lines.length; i++) if (lines[i].trim() === marker) { end = i; break; }
  if (end < 0) return null;
  const pad = lines[end].length - lines[end].trimStart().length;
  const body = lines.slice(start + 1, end).map((l) => (l.trim() ? l.slice(pad) : ""));
  return enc.encode((body.join("\n") + "\n").replaceAll("$$", "$"));
}

export function composeImages(appCompose) {
  const text = appCompose.docker_compose_file || "";
  return Array.from(text.matchAll(/^\s*image:\s*["']?([^\s"'#]+)/gm), (m) => m[1]);
}

class Result {
  constructor() {
    this.checks = [];
    this.keyset = null;
    this.keyset_digest = null;
    this.compose_hash = null;
    this.app_id = null;
    this.collateral = null;
    this.measurements = {};
    this.trace = {};
    this.api_version = null;
    this.app_compose = null;
  }
  add(name, status, detail = "") { this.checks.push({ name, status, detail }); }
  get failed() { return this.checks.filter((c) => c.status === "FAIL"); }
}

function ts(t) {
  const d = new Date(t * 1000);
  const p = (x) => String(x).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`;
}

function vmConfig(ev) {
  const v = ev.vm_config;
  if (typeof v === "string") { try { return JSON.parse(v); } catch { return {}; } }
  return v || {};
}

function decodeUtf8(h) {
  if (!h) return null;
  try { return new TextDecoder("utf-8", { fatal: true }).decode(hexToBytes(h)); } catch { return h; }
}

function errText(e) {
  return e && e.message ? e.message : String(e);
}

export async function verifyReport(report, nonceHex, opts = {}) {
  const {
    label = "", quoteVerifier, collateral = null, requireCompose = true, expectComposeHash = null,
    expectImage = null, expectSource = null, allowImages = null, allowRtmr0 = null, strictTcb = false, strictImage = false,
    approved = null,
  } = opts;
  const now = Math.floor(opts.now ?? Date.now() / 1000);
  const r = new Result();
  r.api_version = report.api_version ?? null;
  const p = label || "";
  const att = report.attestation || {};
  const ev = att.evidence || {};
  const keyset = att.workload_keyset;

  let quote, td;
  try {
    quote = hexToBytes(String(ev.quote).replace(/^0x/, ""));
    td = parseTdReport(quote);
    r.trace.quote = { size: quote.length, sha256: bytesToHex(await sha256(quote)), hex: bytesToHex(quote),
                      fields: Object.fromEntries(Object.entries(td).map(([k, v]) => [k, v instanceof Uint8Array ? bytesToHex(v) : v])) };
  } catch (e) {
    r.add(`${p}读取 quote`, "FAIL", `无法解析：${errText(e)}`);
    return r;
  }

  try {
    const v = await quoteVerifier(quote, collateral, now);
    r.collateral = v.collateral;
    r.trace.tcb = { status: v.status, advisory_ids: v.advisory_ids || [] };
    r.trace.collateral_given = Boolean(collateral);
    const adv = (v.advisory_ids || []).join(", ");
    const detail = `TCB 状态 ${v.status}` + (adv ? `；公告 ${adv}` : "");
    if (v.status === TCB_LOCAL) r.add(`${p}硬件证明：Intel TDX quote 签名链`, "WARN", "本地调试：这份 quote 来自模拟的 dstack 接口，没有 Intel 签名，跳过验签");
    else if (TCB_PASS.has(v.status)) r.add(`${p}硬件证明：Intel TDX quote 签名链`, "PASS", detail);
    else if (TCB_WARN.has(v.status) && !strictTcb) {
      r.add(`${p}硬件证明：Intel TDX quote 签名链`, "WARN", detail + "（签名有效，但平台补丁不是最新）");
    } else r.add(`${p}硬件证明：Intel TDX quote 签名链`, "FAIL", detail);
  } catch (e) {
    r.add(`${p}硬件证明：Intel TDX quote 签名链`, "FAIL", errText(e));
  }

  const debug = Boolean(td.td_attributes[0] & 0x01);
  r.add(`${p}非调试模式（TD_ATTRIBUTES.DEBUG = 0）`, debug ? "FAIL" : "PASS", debug ? "调试模式下宿主机可以读内存" : "");

  if (!keyset || typeof keyset !== "object" || Array.isArray(keyset)) {
    r.add(`${p}绑定公钥与 nonce`, "FAIL", "报告里没有 workload_keyset");
  } else {
    r.keyset = keyset;
    const digest = await keysetDigest(keyset);
    r.keyset_digest = digest;
    const claimed = report.workload_keyset_digest;
    if (claimed !== undefined && claimed !== null && claimed !== digest) {
      r.add(`${p}绑定公钥与 nonce`, "FAIL", `报告声称摘要 ${claimed}，重算得 ${digest}`);
    } else {
      const want = await expectedReportData(digest, nonceHex);
      const ok = bytesEqual(td.report_data, want);
      r.trace.binding = { nonce: nonceHex, keyset_digest: digest, statement: new TextDecoder().decode(statement(digest, nonceHex)),
                          expected: bytesToHex(want), actual: bytesToHex(td.report_data) };
      r.add(`${p}绑定公钥与 nonce（report_data）`, ok ? "PASS" : "FAIL", ok
        ? `sha256(公钥集+本次 nonce) = ${bytesToHex(want.slice(0, 32))}`
        : `quote 里是 ${bytesToHex(td.report_data)}，应为 ${bytesToHex(want)}`);
    }
    let notAfter = keyset.not_after;
    if (notAfter === undefined || notAfter === null) notAfter = (keyset.keyset_epoch || {}).not_after;
    if (!Number.isInteger(notAfter)) r.add(`${p}公钥集有效期`, "FAIL", "缺少 not_after");
    else if (now >= notAfter) r.add(`${p}公钥集有效期`, "FAIL", `已于 ${ts(notAfter)} 过期`);
    else if (notAfter > now + 400 * 86400) r.add(`${p}公钥集有效期`, "WARN", "到期时间过远，相当于不过期");
    else r.add(`${p}公钥集有效期`, "PASS", `到 ${ts(notAfter)}`);
  }

  let named = {};
  try {
    const events = parseEventLog(ev.event_log);
    const rep = await replayRtmr3(events);
    named = rep.named;
    r.trace.events = events;
    r.trace.replay = { steps: rep.steps, result: bytesToHex(rep.mr), quote: bytesToHex(td.rt_mr3) };
    r.trace.boot = {};
    for (const i of [0, 1, 2]) r.trace.boot[i] = { ...(await replayImr(events, i)), quote: bytesToHex(td[`rt_mr${i}`]) };
    if (rep.errors.length) r.add(`${p}事件日志重放 = quote 中的 RTMR3`, "FAIL", rep.errors.slice(0, 3).join("；"));
    else if (!bytesEqual(rep.mr, td.rt_mr3)) {
      r.add(`${p}事件日志重放 = quote 中的 RTMR3`, "FAIL", "重算值和 quote 不一致，事件日志被改过");
    } else {
      const n = Object.values(named).reduce((s, v) => s + v.length, 0);
      r.add(`${p}事件日志重放 = quote 中的 RTMR3`, "PASS", `${n} 条运行时事件逐条核对`);
    }
  } catch (e) {
    r.add(`${p}事件日志重放 = quote 中的 RTMR3`, "FAIL", errText(e));
  }
  const appId = (named["app-id"] || [null])[0];
  r.app_id = appId;

  const mrs = { mrtd: bytesToHex(td.mr_td), rtmr0: bytesToHex(td.rt_mr0), rtmr1: bytesToHex(td.rt_mr1), rtmr2: bytesToHex(td.rt_mr2) };
  const refImages = { ...KNOWN_PROD_IMAGES, ...(allowImages || {}) };
  const image = Object.keys(refImages).find((n) => {
    const ref = refImages[n];
    return ref.mrtd.includes(mrs.mrtd) && mrs.rtmr1 === ref.rtmr1 && mrs.rtmr2 === ref.rtmr2;
  }) || null;
  if (image) {
    r.add(`${p}系统镜像是官方正式版（固件、内核、rootfs 的度量）`, "PASS", `${image}：MRTD、RTMR1、RTMR2 与发布包算出的值一致`);
  } else {
    r.add(`${p}系统镜像是官方正式版（固件、内核、rootfs 的度量）`, strictImage ? "FAIL" : "WARN",
      `MRTD ${mrs.mrtd} RTMR2 ${mrs.rtmr2} 不在已知正式镜像里；dev 镜像可被 SSH 登录。` +
      "核对后用 dstack-mr 算出参考值，用 --allow-image 加入");
  }
  const rtmr0s = { ...KNOWN_RTMR0, ...(allowRtmr0 || {}) };
  r.add(`${p}虚拟硬件配置（RTMR0）与参考值一致`, mrs.rtmr0 in rtmr0s ? "PASS" : strictImage ? "FAIL" : "WARN",
    rtmr0s[mrs.rtmr0] || `RTMR0 ${mrs.rtmr0} 没有参考值；用 dstack-mr diagnose 按 vm_config 算出后用 --allow-rtmr0 加入`);

  const measured = named["compose-hash"] || [];
  const raw = ev.app_compose;
  let appCompose = null;
  if (measured.length !== 1) {
    r.add(`${p}部署配置哈希（compose-hash）`, requireCompose ? "FAIL" : "WARN", `事件日志里有 ${measured.length} 条 compose-hash`);
  } else if (typeof raw !== "string") {
    r.add(`${p}部署配置哈希（compose-hash）`, requireCompose ? "FAIL" : "WARN", "报告没给出 app_compose 原文，无法核对代码");
  } else {
    const h = bytesToHex(await sha256(raw));
    r.compose_hash = measured[0];
    r.trace.compose = { raw, sha256: h, measured: measured[0] };
    const ok = h === measured[0];
    r.add(`${p}部署配置哈希：sha256(app_compose) = 度量值`, ok ? "PASS" : "FAIL",
      ok ? `compose_hash ${measured[0]}` : `原文哈希 ${h}，度量值 ${measured[0]}`);
    if (ok) { try { appCompose = JSON.parse(raw); } catch { appCompose = null; } }
  }

  if (appCompose !== null && typeof appCompose === "object") {
    const images = composeImages(appCompose);
    const unpinned = images.filter((i) => !i.includes("@sha256:"));
    if (!images.length) r.add(`${p}镜像按 digest 固定`, "WARN", "docker_compose_file 里没找到 image");
    else if (unpinned.length) {
      r.add(`${p}镜像按 digest 固定`, "WARN", `未固定：${unpinned.join(", ")}（标签可被替换，compose-hash 锁不住代码）`);
    } else r.add(`${p}镜像按 digest 固定`, "PASS", images.join("；"));
    const allowed = new Set(appCompose.allowed_envs || []);
    const risky = LOGIN_ENVS.filter((e) => allowed.has(e)).sort();
    if (image) {
      r.add(`${p}无法用 SSH 公钥 / root 密码登录`, "PASS", `${image} 正式镜像里没有 SSH 服务和登录程序；` +
        (risky.length ? `allowed_envs 含 ${risky.join(", ")}，在正式镜像里无效` : "allowed_envs 不含 root 密码和 SSH 公钥变量"));
    } else if (risky.length) {
      r.add(`${p}无法用 SSH 公钥 / root 密码登录`, "FAIL", `系统镜像不是已知正式版，且 allowed_envs 含 ${risky.join(", ")}`);
    } else {
      r.add(`${p}无法用 SSH 公钥 / root 密码登录`, "WARN", "系统镜像不是已知正式版，无法确认镜像里没有 SSH 服务；宿主机还能通过 user_config 写入 SSH 公钥");
    }
    if (expectImage) {
      const want = expectImage.split("@").pop();
      const ok = want.startsWith("sha256:") && images.some((i) => i.split("@").pop() === want);
      r.add(`${p}镜像 digest 与我们发布的一致`, ok ? "PASS" : "FAIL", `预期 ${want}`);
    }
    if (expectSource !== null && expectSource !== undefined) {
      const got = embeddedSource(appCompose.docker_compose_file || "");
      if (got !== null) r.trace.source = { text: new TextDecoder().decode(got), sha256: bytesToHex(await sha256(got)), expected_sha256: bytesToHex(await sha256(expectSource)) };
      if (got === null) r.add(`${p}内嵌源码与本地文件一致`, "FAIL", "部署配置里没有内嵌源码");
      else {
        const ok = bytesEqual(got, expectSource);
        r.add(`${p}内嵌源码与本地文件一致`, ok ? "PASS" : "FAIL",
          `sha256 ${bytesToHex(await sha256(got))}` + (ok ? "" : `，本地为 ${bytesToHex(await sha256(expectSource))}`));
      }
    }
    const settings = {};
    for (const k of ["name", "runner", "kms_enabled", "gateway_enabled", "public_logs", "public_sysinfo",
                     "secure_time", "no_instance_id", "allowed_envs"]) {
      if (k in appCompose) settings[k] = appCompose[k];
    }
    if (appCompose.pre_launch_script) settings.pre_launch_script = "有（已被 compose-hash 覆盖）";
    r.measurements.app_compose_settings = settings;
    r.trace.app_compose = appCompose;
    r.app_compose = appCompose;
    r.trace.images = images;
    r.trace.login_envs = { allowed_envs: appCompose.allowed_envs || [], risky, watched: LOGIN_ENVS };
  }
  if (expectComposeHash) {
    const ok = r.compose_hash === expectComposeHash.toLowerCase().replace(/^0x/, "");
    r.add(`${p}compose-hash 与发布记录一致`, ok ? "PASS" : "FAIL", `预期 ${expectComposeHash}`);
  }
  if (approved) {
    const hit = approved.find((a) => a.compose_hash === r.compose_hash && a.app_id === appId);
    r.add(`${p}部署是已批准的那一份（app_id、compose-hash）`, hit ? "PASS" : "FAIL",
          hit ? `${hit.note || "已批准"} · ${appId}` : `app_id ${appId ?? "None"} · compose-hash ${r.compose_hash ?? "None"} 不在已批准列表里`);
    const logs = r.app_compose ? r.app_compose.public_logs : undefined;
    r.add(`${p}容器日志不公开（public_logs = false）`, logs === false ? "PASS" : "FAIL", `public_logs ${logs ?? "None"}`);
  }

  const osHashes = named["os-image-hash"] || [];
  r.trace.vm_config = vmConfig(ev);
  r.trace.mrs = { ...mrs, rtmr3: bytesToHex(td.rt_mr3) };
  r.trace.now = now;
  r.trace.image_ref = image ? { name: image, ...refImages[image] } : null;
  r.trace.rtmr0_ref = rtmr0s[mrs.rtmr0] || null;
  r.trace.keyset = keyset ?? null;
  Object.assign(r.measurements, {
    mr_td: mrs.mrtd, rtmr0: mrs.rtmr0, rtmr1: mrs.rtmr1, rtmr2: mrs.rtmr2,
    rtmr3: bytesToHex(td.rt_mr3),
    image,
    app_id: appId,
    compose_hash: r.compose_hash,
    instance_id: (named["instance-id"] || [null])[0],
    os_image_hash: image ? refImages[image].os_image_hash ?? null : null,
    os_image_hash_self_reported: osHashes.length === 1 ? osHashes[0] : null,
    os_image_hash_host_claimed: vmConfig(ev).os_image_hash ?? null,
    key_provider: decodeUtf8((named["key-provider"] || [null])[0]),
  });
  return r;
}

export function receiptEvent(receipt, etype) {
  return (receipt.event_log || []).find((e) => e.type === etype) || null;
}

export function receiptHash(event) {
  if (!event) return null;
  return event.body_hash || event.wire_hash || null;
}

export async function verifyReceiptSignature(receipt, keyset, apiVersion = null) {
  const name = "回执签名（公钥来自已验证的证明）";
  if (apiVersion !== null && receipt.api_version !== apiVersion) {
    return { name, status: "FAIL", detail: `回执 api_version ${receipt.api_version ?? "None"}，应为 ${apiVersion}` };
  }
  const keys = keyset.receipt_signing_keys || [];
  let key = keys.find((k) => k.key_id === receipt.key_id) || null;
  if (key === null && keys.length === 1 && !("key_id" in receipt)) key = keys[0];
  if (key === null) return { name, status: "FAIL", detail: `key_id ${receipt.key_id ?? "None"} 不在已证明的公钥集里` };
  const doc = { ...receipt };
  delete doc.signature;
  let payload;
  try { payload = jcs(doc); } catch (e) { return { name, status: "FAIL", detail: errText(e) }; }
  if (key.algo !== "ed25519") {
    return { name, status: "WARN", detail: `本脚本未实现 ${key.algo} 验签，可用 Phala 的 pap verify 交叉核对` };
  }
  try {
    const pub = await subtle.importKey("raw", hexToBytes(key.public_key), { name: "Ed25519" }, false, ["verify"]);
    const ok = await subtle.verify({ name: "Ed25519" }, pub, hexToBytes(receipt.signature || ""), payload);
    return ok ? { name, status: "PASS", detail: `Ed25519，key_id ${key.key_id}` + (apiVersion !== null ? `，api_version ${apiVersion}` : "") }
      : { name, status: "FAIL", detail: "签名无效 " };
  } catch (e) {
    return { name, status: "FAIL", detail: `签名无效 ${errText(e)}` };
  }
}

export function findE2eeKey(keyset, algo = MVP_E2EE_ALGO) {
  return (keyset.e2ee_public_keys || []).find((k) => k.algo === algo) || null;
}

export class ClientChannel {
  static async create(serverKey, digest) {
    const ch = new ClientChannel();
    ch.serverKey = serverKey;
    ch.digest = digest;
    const serverPub = hexToBytes(serverKey.public_key);
    const kp = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    ch.clientPub = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
    const peer = await subtle.importKey("raw", serverPub, { name: "X25519" }, false, []);
    const shared = await subtle.deriveBits({ name: "X25519", public: peer }, kp.privateKey, 256);
    const hk = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
    const keyBytes = await subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: concat(MVP_HKDF_INFO, ch.clientPub, serverPub) }, hk, 256);
    ch.key = await subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    return ch;
  }

  async seal(plaintext, b64 = false) {
    this.reqNonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await subtle.encrypt(
      { name: "AES-GCM", iv: this.reqNonce, additionalData: concat("pa-mvp/req/v1|", this.digest) }, this.key, plaintext));
    const head = { key_id: this.serverKey.key_id, client_public_key: bytesToHex(this.clientPub), nonce: bytesToHex(this.reqNonce) };
    return b64 ? { ...head, ciphertext_b64: bytesToB64(ct) } : { ...head, ciphertext: bytesToHex(ct) };
  }

  async openFrame(f) {
    return new Uint8Array(await subtle.decrypt(
      { name: "AES-GCM", iv: hexToBytes(f.nonce), additionalData: concat("pa-mvp/stream/v1|", this.digest, "|", this.reqNonce, "|", String(f.seq)) },
      this.key, hexToBytes(f.ciphertext)));
  }

  async openReceipt(sealed) {
    try {
      return JSON.parse(new TextDecoder().decode(await subtle.decrypt(
        { name: "AES-GCM", iv: hexToBytes(sealed.nonce), additionalData: concat("pa-mvp/receipt/v1|", this.digest, "|", this.reqNonce) },
        this.key, hexToBytes(sealed.ciphertext))));
    } catch {
      return null;
    }
  }

  async open(resp) {
    try {
      return new Uint8Array(await subtle.decrypt(
        { name: "AES-GCM", iv: hexToBytes(resp.nonce), additionalData: concat("pa-mvp/resp/v1|", this.digest, "|", this.reqNonce) },
        this.key, resp.ciphertext_b64 !== undefined ? b64ToBytes(resp.ciphertext_b64) : hexToBytes(resp.ciphertext)));
    } catch {
      throw new Error("解密失败");
    }
  }
}

async function collateralKey(quote) {
  return bytesToHex(await sha256(quote.slice(Math.max(0, quote.length - 4096))));
}

export function verifierFrom(api, pccsUrl) {
  const cache = new Map();
  return async (quote, collateral, now) => {
    let col = collateral;
    if (!col) {
      const key = await collateralKey(quote);
      const hit = cache.get(key);
      if (hit && Date.now() - hit.at < COLLATERAL_TTL_MS) col = hit.col;
      else {
        col = await api.js_get_collateral(pccsUrl, quote);
        cache.set(key, { col, at: Date.now() });
      }
    }
    const v = api.js_verify(quote, col, BigInt(Math.floor(now)));
    return { status: v.status, advisory_ids: v.advisory_ids || [], collateral: col };
  };
}

export function localQuoteVerifier() {
  return async () => ({ status: TCB_LOCAL, advisory_ids: [], collateral: null });
}

let wasmReady = null;

export async function createQuoteVerifier(pccsUrl) {
  wasmReady ||= init({ module_or_path: new URL("./dcap-qvl-web_bg.wasm", import.meta.url) });
  await wasmReady;
  return verifierFrom({ js_get_collateral, js_verify }, pccsUrl);
}

export function fmspcOf(collateral) {
  try {
    const t = typeof collateral.tcb_info === "string" ? JSON.parse(collateral.tcb_info) : collateral.tcb_info;
    return (t.fmspc || t.tcbInfo?.fmspc || "").toUpperCase() || null;
  } catch {
    return null;
  }
}

export class ServiceError extends Error {}

export async function httpJson(method, url, body) {
  let r;
  try {
    r = await fetch(url, { method, cache: "no-store", headers: body ? { "Content-Type": "application/json" } : {},
                          body: body ? JSON.stringify(body) : undefined });
  } catch {
    throw new ServiceError("连接失败");
  }
  const text = await r.text();
  if (!r.ok) throw new ServiceError(`HTTP ${r.status}`);
  try { return JSON.parse(text); } catch { throw new ServiceError("响应格式错误"); }
}

function eqCheck(name, got, want) {
  const same = got !== null && got !== undefined && JSON.stringify(got) === JSON.stringify(want);
  return { name, status: same ? "PASS" : "FAIL",
           detail: same ? "" : `得到 ${JSON.stringify(got)}，应为 ${JSON.stringify(want)}` };
}

export async function verifyCvm(base, args) {
  const nonce = randomHex(32);
  const report = await httpJson("GET", `${base}/v1/attestation?nonce=${nonce}`);
  const res = await verifyReport(report, nonce, {
    quoteVerifier: args.cvmQuoteVerifier || args.quoteVerifier, collateral: ((report.attestation || {}).evidence || {}).collateral || null,
    requireCompose: true, expectComposeHash: args.expectComposeHash,
    expectImage: args.expectImage, expectSource: args.expectSource, strictTcb: args.strictTcb ?? true,
    strictImage: args.strictImage ?? true, approved: args.approved ?? null,
  });
  res.checks.unshift({ name: "本次随机 nonce（防重放）", status: "INFO", detail: nonce });
  return { res, report, nonce };
}

export async function chat(base, res, inner, token, extra = {}) {
  const checks = [];
  const key = findE2eeKey(res.keyset);
  if (key === null) return { checks: [{ name: "加密通道", status: "FAIL", detail: "证明里没有本 MVP 的加密公钥" }], out: null };
  const ch = await ClientChannel.create(key, res.keyset_digest);
  const gatewayNonce = randomHex(32);
  const body = { ...inner, gateway_nonce: gatewayNonce, sent_at: Date.now() / 1000 };
  if (token) body.access_token = token;
  if (extra.sessionId) body.session_id = extra.sessionId;
  if (extra.reverify) body.reverify = true;
  if (extra.knownNonces) extra.knownNonces.add(gatewayNonce);
  const reqPlain = new TextEncoder().encode(JSON.stringify(body));
  const envelope = await ch.seal(reqPlain, Boolean(extra.b64));
  const resp = await httpJson("POST", `${base}/v1/chat`, envelope);
  const shown = token ? { ...body, access_token: "*".repeat(8) } : body;
  const trace = { server_key: key, client_public_key: bytesToHex(ch.clientPub), keyset_digest: res.keyset_digest,
                  request: { envelope, plain: shown, size: reqPlain.length, sha256: await sha256Tag(reqPlain) },
                  response: { envelope: { nonce: resp.nonce, ciphertext: resp.ciphertext ?? resp.ciphertext_b64 } }, receipt: null };
  let respPlain;
  try {
    respPlain = await ch.open(resp);
  } catch (e) {
    return { checks: [{ name: "加密通道：只有被证明的 CVM 能解开", status: "FAIL", detail: errText(e) }], out: null, trace };
  }
  const respText = new TextDecoder().decode(respPlain);
  trace.response.plain = JSON.parse(respText);
  trace.response.size = respPlain.length;
  trace.response.sha256 = await sha256Tag(respPlain);
  checks.push({ name: "加密通道：消息用证明里的公钥加密，CVM 解密并加密回复", status: "PASS",
                detail: `X25519 + AES-256-GCM，公钥 ${key.public_key}` });
  const out = JSON.parse(respText);
  const receipt = (resp.receipt_sealed && (await ch.openReceipt(resp.receipt_sealed))) || {};
  trace.receipt = receipt;
  checks.push(await verifyReceiptSignature(receipt, res.keyset, res.api_version));
  checks.push(eqCheck("CVM 回执：公钥集摘要一致", receipt.workload_keyset_digest, res.keyset_digest));
  checks.push(eqCheck("CVM 回执：请求哈希 = 我发出的内容", receiptHash(receiptEvent(receipt, "request.received")), await sha256Tag(reqPlain)));
  checks.push(eqCheck("CVM 回执：回复哈希 = 我收到的内容", receiptHash(receiptEvent(receipt, "response.returned")), await sha256Tag(respPlain)));
  out._gateway_nonce = gatewayNonce;
  out._messages = inner.messages;
  return { checks, out, trace };
}

export function b64ToBytes(s) {
  return Uint8Array.from(atob(s || ""), (c) => c.charCodeAt(0));
}

function minutesAgo(t, now) {
  return Math.max(0, Math.round((now - t) / 60));
}

export function upstreamNonce(p, used, current, reused, args) {
  const now = Math.floor(args.now ?? Date.now() / 1000);
  if (!reused) return { name: `${p}本次随机数`, status: used === current ? "INFO" : "FAIL", detail: current };
  const known = Boolean(args.knownNonces && args.knownNonces.has(used));
  const fresh = Number.isFinite(reused.verified_at) && now - reused.verified_at <= (args.sessionTtl ?? SESSION_TTL) + 60;
  return { name: `${p}沿用本会话的上游验证`, status: known && fresh ? "INFO" : "FAIL",
           detail: !known ? `证明里的随机数 ${String(used).slice(0, 16)}… 不是本会话发出过的`
             : !fresh ? `沿用的验证已超过 ${Math.round((args.sessionTtl ?? SESSION_TTL) / 60)} 分钟`
             : `沿用 ${minutesAgo(reused.verified_at, now)} 分钟前的验证；证明里的随机数 ${used.slice(0, 16)}… 是本会话之前发出的，下面的检查针对那份证明重新做一遍` };
}

export async function verifyGateway(out, args) {
  const checks = [];
  if (out.error) return { checks: [{ name: "推理调用", status: "FAIL", detail: out.error }], report: null, trace: null };
  const gw = out.gateway_attestation || {};
  const gwNonce = out.gateway_nonce || out._gateway_nonce;
  if (out.reused) checks.push(upstreamNonce("网关 · ", gwNonce, out._gateway_nonce, out.reused, args));
  let gres = null;
  if (!("attestation" in gw)) {
    checks.push({ name: "网关证明", status: "FAIL", detail: `没拿到网关证明：${JSON.stringify(gw)}` });
  } else {
    gres = await verifyReport(gw, gwNonce, { label: "网关 · ", quoteVerifier: args.quoteVerifier, collateral: out.gateway_collateral || null,
                                                        requireCompose: false, strictTcb: args.strictTcb });
    checks.push(...gres.checks);
    const prov = (gw.attestation || {}).source_provenance || {};
    if (Object.keys(prov).length) {
      gres.provenance = prov;
      checks.push(provenanceCheck(prov, gres.app_compose));
    }
  }
  const st = out.upstream_status;
  checks.push({ name: "推理请求经网关返回", status: st === 200 ? "PASS" : "FAIL", detail: `HTTP ${st ?? "None"}，模型 ${out.model ?? "None"}` });
  const reqBytes = b64ToBytes(out.upstream_request_b64);
  const respBytes = b64ToBytes(out.upstream_response_b64);
  const dec = new TextDecoder();
  const trace = { attestation: gw, status: st ?? null, model: out.model ?? null, receipt_id: out.receipt_id ?? null,
                  receipt: out.receipt || null, messages: out._messages, spki: out.observed_tls_spki_sha256 ?? null,
                  request: { text: dec.decode(reqBytes), size: reqBytes.length, sha256: await sha256Tag(reqBytes) },
                  response: { text: dec.decode(respBytes), size: respBytes.length, sha256: await sha256Tag(respBytes) } };
  let sentMsgs = null;
  try { sentMsgs = JSON.parse(new TextDecoder().decode(reqBytes)).messages ?? null; } catch { sentMsgs = null; }
  if (args.agent) {
    const hit = (sentMsgs || []).some((m) => m.role === "user" && JSON.stringify(m.content ?? "").includes(JSON.stringify(args.agent.text || "").slice(1, -1)));
    checks.push({ name: "agent 发给网关的请求里有我这条消息", status: hit || !args.agent.text ? "PASS" : out.aux ? "INFO" : "WARN",
                  detail: `${(sentMsgs || []).length} 条消息 · 第 ${out.call ?? 1} 次调用` + (out.aux ? " · 辅助调用" : "") });
  } else checks.push(eqCheck("CVM 发给网关的就是我的消息（未被改写）", sentMsgs, out._messages));

  const receipt = out.receipt;
  if (!receipt) {
    checks.push({ name: "网关回执", status: "FAIL", detail: `没拿到回执（receipt id ${out.receipt_id ?? "None"}）` });
    return { checks, report: gres, trace };
  }
  if (gres === null || gres.keyset === null) {
    checks.push({ name: "网关回执", status: "FAIL", detail: "网关证明未通过，回执无从核对" });
    return { checks, report: gres, trace };
  }
  checks.push(await verifyReceiptSignature(receipt, gres.keyset, gres.api_version || "aci/1"));
  checks.push(eqCheck("网关回执：公钥集摘要 = 刚验证过的网关", receipt.workload_keyset_digest, gres.keyset_digest));
  if (gw.workload_id && receipt.workload_id) checks.push(eqCheck("网关回执：workload_id 一致", receipt.workload_id, gw.workload_id));
  checks.push(eqCheck("网关回执：请求哈希 = CVM 实际发出的字节", receiptHash(receiptEvent(receipt, "request.received")), await sha256Tag(reqBytes)));
  checks.push(eqCheck("网关回执：回复哈希 = CVM 实际收到的字节", receiptHash(receiptEvent(receipt, "response.returned")), await sha256Tag(respBytes)));
  const up = receiptEvent(receipt, "upstream.verified") || {};
  const route = (receiptEvent(receipt, "route.selected") || {}).target_route_id;
  const good = up.result === "verified" && up.required === true && Boolean(up.session_id);
  checks.push({ name: "网关回执：上游 TEE 已验证（网关声明，upstream.verified）", status: good ? "PASS" : "FAIL",
                detail: `result=${up.result ?? "None"} required=${up.required === undefined ? "None" : up.required ? "True" : "False"} ` +
                        `model=${up.model_id ?? "None"} route=${route ?? "None"} session=${up.session_id ?? "None"}` });
  checks.push(tlsCheck(gres.keyset.tls_public_keys || [], out.observed_tls_spki_sha256, args.gatewayHost || GATEWAY_HOST));
  return { checks, report: gres, trace };
}

export function hostMatches(domain, host) {
  const d = String(domain || "").toLowerCase().replace(/\.$/, "");
  const h = String(host || "").toLowerCase();
  if (d.startsWith("*.")) return h.endsWith(d.slice(1)) && !h.slice(0, -d.length + 1).includes(".");
  return d === h;
}

export function tlsCheck(entries, spki, host) {
  const name = "CVM→网关 TLS 公钥在证明里";
  if (!entries.length) return { name, status: "WARN", detail: "网关证明没列出 TLS 公钥，这一段只能依赖普通 HTTPS 证书" };
  const scoped = entries.some((k) => k.domain);
  const mine = scoped ? entries.filter((k) => hostMatches(k.domain, host)) : entries;
  if (!mine.length) return { name, status: "FAIL", detail: `网关证明里没有 ${host} 的 TLS 公钥` };
  const ok = mine.some((k) => k.spki_sha256 === spki);
  return { name, status: ok ? "PASS" : "FAIL", detail: `${scoped ? host : "任一条目"}：观察到 ${spki ?? "None"}` };
}

export function composeRepoCommits(appCompose) {
  const text = (appCompose && appCompose.docker_compose_file) || "";
  const found = Array.from(text.matchAll(/PRIVATE_AI_GATEWAY_REPO_COMMIT\s*[=:]\s*["']?([0-9a-fA-F]{40})\b/g), (m) => m[1].toLowerCase());
  return [...new Set(found)];
}

export function provenanceCheck(prov, appCompose) {
  const name = "网关 · 源码出处（与度量配置中的 REPO_COMMIT 比对）";
  const claimed = String(prov.repo_commit ?? "").toLowerCase();
  const head = `${prov.repo_url ?? "None"} @ ${prov.repo_commit ?? "None"}`;
  const measured = composeRepoCommits(appCompose);
  if (!measured.length) return { name, status: "WARN", detail: `${head}；度量配置里没有 PRIVATE_AI_GATEWAY_REPO_COMMIT，无法佐证` };
  if (measured.length === 1 && measured[0] === claimed) {
    return { name, status: "INFO", detail: `${head}；与度量配置里的 PRIVATE_AI_GATEWAY_REPO_COMMIT 一致` };
  }
  return { name, status: "WARN", detail: `${head}；度量配置里是 ${measured.join(", ")}` };
}

function tlv(buf, off) {
  let len = buf[off + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off + 2 + i];
    hdr = 2 + n;
  }
  return { tag: buf[off], start: off, body: off + hdr, end: off + hdr + len };
}

function derChildren(buf, t) {
  const out = [];
  for (let o = t.body; o < t.end;) { const c = tlv(buf, o); out.push(c); o = c.end; }
  return out;
}

function derTime(der, t) {
  const s = new TextDecoder().decode(der.slice(t.body, t.end));
  const y = t.tag === 0x17 ? (Number(s.slice(0, 2)) < 50 ? 2000 : 1900) + Number(s.slice(0, 2)) : Number(s.slice(0, 4));
  const r = s.slice(t.tag === 0x17 ? 2 : 4);
  return Date.UTC(y, Number(r.slice(0, 2)) - 1, Number(r.slice(2, 4)), Number(r.slice(4, 6)), Number(r.slice(6, 8)), Number(r.slice(8, 10))) / 1000;
}

export function parseCert(der) {
  const [tbs, alg, sig] = derChildren(der, tlv(der, 0));
  const fields = derChildren(der, tbs);
  const v = fields[0].tag === 0xa0 ? 1 : 0;
  const spki = fields[5 + v];
  const [nb, na] = derChildren(der, fields[3 + v]);
  const oid = derChildren(der, alg)[0];
  return { tbs: der.slice(tbs.start, tbs.end), spki: der.slice(spki.start, spki.end), notBefore: derTime(der, nb), notAfter: derTime(der, na),
           alg: bytesToHex(der.slice(oid.body, oid.end)), sig: der.slice(sig.body + 1, sig.end) };
}

function ecdsaRaw(sig, n) {
  const [r, s] = derChildren(sig, tlv(sig, 0));
  const fix = (t) => {
    let v = sig.slice(t.body, t.end);
    while (v.length > n && v[0] === 0) v = v.slice(1);
    const o = new Uint8Array(n);
    o.set(v, n - v.length);
    return o;
  };
  return concat(fix(r), fix(s));
}

const OID_RSA_SHA256 = "2a864886f70d01010b";
const OID_ECDSA_SHA384 = "2a8648ce3d040303";

async function certIssuedBy(child, parentSpki) {
  if (child.alg === OID_RSA_SHA256) {
    const k = await subtle.importKey("spki", parentSpki, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    return subtle.verify("RSASSA-PKCS1-v1_5", k, child.sig, child.tbs);
  }
  if (child.alg === OID_ECDSA_SHA384) {
    const k = await subtle.importKey("spki", parentSpki, { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
    return subtle.verify({ name: "ECDSA", hash: "SHA-384" }, k, ecdsaRaw(child.sig, 48), child.tbs);
  }
  throw new Error(`不支持的证书签名算法 ${child.alg}`);
}

function b64url(s) {
  return b64ToBytes(String(s).replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
}

const jsonOf = (b) => JSON.parse(new TextDecoder().decode(b));
const asObj = (v) => (typeof v === "string" ? JSON.parse(v) : v);

export async function verifyNrasTokens(nr, nonceHex, models, now) {
  const tokens = (nr && nr.tokens) || [];
  if (!tokens.length) throw new Error("没有 NVIDIA 令牌");
  const claims = [];
  for (const t of tokens) {
    const [h, p, s] = t.split(".");
    const hdr = jsonOf(b64url(h));
    if (hdr.alg !== "ES384") throw new Error(`令牌算法 ${hdr.alg}`);
    const x5c = (nr.keys || {})[hdr.kid];
    if (!x5c) throw new Error(`kid ${hdr.kid} 没有对应证书`);
    const leaf = parseCert(b64ToBytes(x5c[0]));
    const inter = parseCert(b64ToBytes(x5c[1]));
    if (!CHUTES_PINS.nras_intermediates.includes(bytesToHex(await sha256(inter.spki)))) throw new Error("签名证书不在固定的 NVIDIA 中间证书下");
    if (!(await certIssuedBy(leaf, inter.spki))) throw new Error("签名证书不是 NVIDIA 中间证书签发的");
    if (!(leaf.notBefore <= now && now <= leaf.notAfter)) throw new Error("签名证书不在有效期内");
    const key = await subtle.importKey("spki", leaf.spki, { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
    if (!(await subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, b64url(s), enc.encode(`${h}.${p}`)))) throw new Error("令牌签名无效");
    const c = jsonOf(b64url(p));
    if (!(c.exp > now)) throw new Error("令牌已过期");
    claims.push(c);
  }
  const overall = claims[0];
  if (overall["x-nvidia-overall-att-result"] !== true) throw new Error("NVIDIA 判定未通过");
  if (overall.eat_nonce !== nonceHex) throw new Error(`令牌随机数 ${overall.eat_nonce}，应为 ${nonceHex}`);
  const gpus = claims.slice(1);
  if (!gpus.length) throw new Error("没有单卡令牌");
  const listed = Object.values(overall.submods || {}).map((v) => (Array.isArray(v) && v[0] === "DIGEST" && Array.isArray(v[1]) && v[1][0] === "SHA-256" ? v[1][1] : ""));
  const have = await Promise.all(tokens.slice(1).map(async (t) => bytesToHex(await sha256(enc.encode(t)))));
  if (listed.length !== have.length || [...listed].sort().join() !== [...have].sort().join()) {
    throw new Error(`单卡令牌和整体令牌里登记的不一致（登记 ${listed.length} 张，收到 ${have.length} 张）`);
  }
  if (gpus.some((c) => c.eat_nonce !== nonceHex)) throw new Error("单卡令牌里的随机数不对");
  const bad = gpus.filter((c) => !(c.measres === "success" && c.secboot === true && c.dbgstat === "disabled"));
  const wrong = models ? gpus.filter((c) => !models.has(c.hwmodel)) : [];
  return { overall, gpus, bad, wrong, tokens: tokens.length };
}

async function tdxChecks(p, quote, args, now, checks, collateral = null) {
  const td = parseTdReport(quote);
  try {
    const v = await args.quoteVerifier(quote, collateral, now);
    checks.push({ name: `${p}Intel TDX quote 签名链`, status: TCB_PASS.has(v.status) ? "PASS" : "FAIL", detail: `TCB 状态 ${v.status}` });
  } catch (e) {
    checks.push({ name: `${p}Intel TDX quote 签名链`, status: "FAIL", detail: errText(e) });
  }
  const debug = Boolean(td.td_attributes[0] & 0x01);
  checks.push({ name: `${p}非调试模式`, status: debug ? "FAIL" : "PASS", detail: debug ? "调试模式下宿主机可以读内存" : "" });
  return td;
}

const regsOf = (td) => ({ mrtd: bytesToHex(td.mr_td), rtmr0: bytesToHex(td.rt_mr0), rtmr1: bytesToHex(td.rt_mr1),
                          rtmr2: bytesToHex(td.rt_mr2), rtmr3: bytesToHex(td.rt_mr3) });

export function chutesRow(r) {
  for (const [version, im] of Object.entries(CHUTES_PINS.images)) {
    if (["mrtd", "rtmr1", "rtmr2", "rtmr3"].every((k) => im[k] === r[k])) {
      const row = CHUTES_PINS.rows.find((x) => x[0] === version && x[2] === r.rtmr0);
      if (row) return row;
    }
  }
  return null;
}

async function gpuChecks(p, nr, nonceHex, models, now, checks) {
  try {
    const g = await verifyNrasTokens(nr, nonceHex, models, now);
    checks.push({ name: `${p}NVIDIA GPU 证明（NRAS）`, status: "PASS",
                  detail: `${g.tokens} 个令牌签名有效，签名证书链到固定的 NVIDIA 中间证书；随机数 = ${nonceHex.slice(0, 16)}…` });
    const ok = !g.bad.length && !g.wrong.length;
    checks.push({ name: `${p}GPU 状态与型号`, status: ok ? "PASS" : "FAIL",
                  detail: `${g.gpus.length} 块 ${[...new Set(g.gpus.map((c) => c.hwmodel))].join("/")}` +
                          (g.bad.length ? `；${g.bad.length} 块度量、安全启动或调试状态不对` : "") +
                          (g.wrong.length ? `；型号 ${g.wrong.map((c) => c.hwmodel).join(",")} 不符` : "") });
    return g;
  } catch (e) {
    checks.push({ name: `${p}NVIDIA GPU 证明（NRAS）`, status: "FAIL", detail: errText(e) });
    return null;
  }
}

function attemptChecks(p, up, checks) {
  for (const a of up.attempts || []) {
    checks.push({ name: `${p}跳过未通过验证的实例`, status: "INFO", detail: `${a.instance_id || a.signing_address || ""}：${a.error}` });
  }
}

export async function verifyChutes(out, args) {
  const p = "Chutes · ";
  const up = out.upstream || {};
  const now = Math.floor(args.now ?? Date.now() / 1000);
  const checks = [];
  checks.push(upstreamNonce(p, up.nonce, out._gateway_nonce, up.reused, args));
  const nonce = up.reused ? up.nonce : out._gateway_nonce;
  const trace = { up, nonce, messages: out._messages, model: out.model, reused: up.reused || null };
  attemptChecks(p, up, checks);
  if (!up.evidence) {
    checks.push({ name: `${p}模型机验证`, status: "FAIL", detail: out.error || "没有拿到证据" });
    return { checks, trace };
  }
  const ev = up.evidence;
  const body = b64ToBytes(ev.attested_body);
  const cert = parseCert(b64ToBytes(ev.certificate));
  trace.cert_spki_sha256 = bytesToHex(await sha256(cert.spki));
  try {
    const k = await subtle.importKey("spki", cert.spki, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const ok = await subtle.verify("RSASSA-PKCS1-v1_5", k, b64ToBytes(ev.signature), body);
    checks.push({ name: `${p}证据签名（实例证书）`, status: ok ? "PASS" : "FAIL", detail: ok ? `RSA-PKCS1v15-SHA256，${body.length} B 原始响应` : "签名无效" });
  } catch (e) {
    checks.push({ name: `${p}证据签名（实例证书）`, status: "FAIL", detail: errText(e) });
  }
  const doc = jsonOf(body);
  trace.doc = doc;
  checks.push(doc.nonce === undefined
    ? { name: `${p}证据里的随机数是本次的`, status: "PASS", detail: "旧格式证据无此字段，由 report_data 绑定" }
    : eqCheck(`${p}证据里的随机数是本次的`, doc.nonce, nonce));
  const quote = b64ToBytes((doc.evidence || {}).tdx_quote || (doc.evidence || {}).quote);
  trace.quote = bytesToHex(quote);
  const td = await tdxChecks(p, quote, args, now, checks, up.collateral || null);
  const rd = bytesToHex(td.report_data);
  trace.report_data = rd;
  checks.push(eqCheck(`${p}quote 绑定实例证书（report_data[32:64]）`, rd.slice(64), trace.cert_spki_sha256));
  const want = bytesToHex(await sha256(nonce + up.e2e_pubkey));
  trace.binding = { nonce, e2e_pubkey: up.e2e_pubkey, expected: want, actual: rd.slice(0, 64) };
  checks.push(eqCheck(`${p}quote 绑定本次随机数和加密公钥（report_data[0:32]）`, rd.slice(0, 64), want));
  const r = regsOf(td);
  const row = chutesRow(r);
  trace.regs = r;
  trace.row = row;
  checks.push({ name: `${p}度量值命中参考值快照（MRTD、RTMR0-3）`, status: row ? "PASS" : "FAIL",
                detail: row ? `Chutes ${row[0]} · ${row[1]}` : `MRTD ${r.mrtd.slice(0, 16)}… 不在 ${CHUTES_PINS.fetched} 的快照里` });
  const gpu = asObj((doc.evidence || {}).nvtrust_evidence) || [];
  trace.gpu_count = gpu.length;
  if (!gpu.length) checks.push({ name: `${p}GPU 数量`, status: "FAIL", detail: "证据里没有 GPU" });
  else if (row && gpu.length > row[4]) checks.push({ name: `${p}GPU 数量`, status: "FAIL", detail: `${gpu.length} 块，参考值最多 ${row[4]} 块` });
  const models = row ? new Set(row[3].flatMap((g) => CHUTES_PINS.gpu_models[g] || [])) : new Set();
  trace.nras = await gpuChecks(p, up.nras, rd.slice(0, 64), models, now, checks);
  if (args.agent) {
    checks.push({ name: `${p}agent 发给模型的请求`, status: "INFO",
                  detail: `${(up.request || {}).messages ?? "?"} 条消息 · ${(up.request || {}).tools ?? 0} 个工具 · 整体加密` });
  } else checks.push(eqCheck(`${p}CVM 发出的就是我的消息`, (up.request || {}).messages ?? null, out._messages));
  const okReply = !out.error && (args.agent ? Boolean(up.response) : typeof out.reply === "string");
  checks.push({ name: `${p}加密发送，只有这台实例能解开`, status: okReply ? "PASS" : "FAIL",
                detail: okReply ? `ML-KEM-768 + ChaCha20-Poly1305 · 请求 ${up.request_ciphertext_bytes} B · 回复 ${up.response_ciphertext_bytes} B` +
                                  (up.stream_chunks ? ` · 流式 ${up.stream_chunks} 块` : "")
                  : out.error || "没有回复" });
  return { checks, trace };
}

function hexOrB64(s) {
  const t = String(s || "").replace(/^0x/, "");
  return /^(?:[0-9a-fA-F]{2})+$/.test(t) ? hexToBytes(t) : b64ToBytes(t);
}

export async function verifyNear(out, args) {
  const p = "NEAR · ";
  const up = out.upstream || {};
  const now = Math.floor(args.now ?? Date.now() / 1000);
  const checks = [];
  checks.push(upstreamNonce(p, up.nonce, out._gateway_nonce, up.reused, args));
  const nonce = up.reused ? up.nonce : out._gateway_nonce;
  const trace = { up, nonce, messages: out._messages, model: out.model, reused: up.reused || null };
  attemptChecks(p, up, checks);
  const att = up.attestation;
  if (!att) {
    checks.push({ name: `${p}模型机验证`, status: "FAIL", detail: out.error || "没有拿到证明" });
    return { checks, trace };
  }
  const quote = hexOrB64(att.intel_quote);
  trace.quote = bytesToHex(quote);
  const td = await tdxChecks(p, quote, args, now, checks, up.collateral || null);
  const rd = bytesToHex(td.report_data);
  const key = String(att.signing_address || "").replace(/^0x/, "").toLowerCase();
  trace.report_data = rd;
  trace.key = key;
  checks.push(eqCheck(`${p}quote 绑定模型公钥（report_data[0:32]）`, rd.slice(0, 64), key));
  checks.push(eqCheck(`${p}quote 绑定本次随机数（report_data[32:64]）`, rd.slice(64), nonce));
  const info = asObj(att.info) || {};
  const tcbInfo = asObj(info.tcb_info) || {};
  const compose = tcbInfo.app_compose || "";
  let named = {};
  try {
    const events = parseEventLog(att.event_log);
    const rep = await replayRtmr3(events);
    named = rep.named;
    trace.events = events;
    trace.replay = { steps: rep.steps, result: bytesToHex(rep.mr), quote: bytesToHex(td.rt_mr3) };
    checks.push({ name: `${p}事件日志重放 = quote 中的 RTMR3`, status: !rep.errors.length && bytesEqual(rep.mr, td.rt_mr3) ? "PASS" : "FAIL",
                  detail: rep.errors.length ? rep.errors.slice(0, 2).join("；") : `${rep.steps.length} 条运行时事件` });
  } catch (e) {
    checks.push({ name: `${p}事件日志重放 = quote 中的 RTMR3`, status: "FAIL", detail: errText(e) });
  }
  const ch = bytesToHex(await sha256(compose));
  const only = (k) => ((named[k] || []).length === 1 ? named[k][0] : null);
  trace.compose = { raw: compose, sha256: ch, measured: only("compose-hash") };
  checks.push(eqCheck(`${p}部署配置哈希：sha256(app_compose) = 度量值`, only("compose-hash"), ch));
  try { trace.app_compose = JSON.parse(compose); } catch { trace.app_compose = null; }
  trace.regs = regsOf(td);
  const r = trace.regs;
  const imageOk = NEAR_PINS.mrtd.includes(r.mrtd) && r.rtmr1 === NEAR_PINS.rtmr1 && r.rtmr2 === NEAR_PINS.rtmr2;
  checks.push({ name: `${p}系统镜像与虚拟硬件（MRTD、RTMR0-2）`, status: imageOk && NEAR_PINS.rtmr0.includes(r.rtmr0) ? "PASS" : "FAIL",
                detail: imageOk ? `${NEAR_PINS.image} · MRTD/RTMR1 与官方 0.5.12 一致 · RTMR2/RTMR0 为 ${NEAR_PINS.observed} 实测` +
                                  (NEAR_PINS.rtmr0.includes(r.rtmr0) ? "" : `；RTMR0 ${r.rtmr0.slice(0, 16)}… 不在参考值里`)
                  : `不是固定的 ${NEAR_PINS.image}` });
  checks.push(eqCheck(`${p}os-image-hash 与参考值一致`, only("os-image-hash"), NEAR_PINS.os_image_hash));
  let kms = null;
  try { kms = JSON.parse(new TextDecoder().decode(hexToBytes(only("key-provider")))).id ?? null; } catch { kms = null; }
  trace.kms = kms;
  checks.push({ name: `${p}密钥来自固定的 NEAR KMS（key-provider）`, status: kms === NEAR_PINS.kms ? "PASS" : "FAIL",
                detail: kms === NEAR_PINS.kms ? `KMS 公钥 ${kms.slice(-32)}` : `key-provider ${kms ?? "缺失"}` });
  const appId = only("app-id");
  trace.app_id = appId;
  trace.instance_id = only("instance-id");
  checks.push({ name: `${p}模型公钥由同一应用的多台机器共用`, status: "WARN",
                detail: `同一 app-id 的机器共用这把公钥，本次验证 ${(trace.instance_id || "?").slice(0, 12)}…，已固定 ${NEAR_PINS.compose_hashes.length} 台配置` });
  const pinned = NEAR_PINS.app_ids.includes(appId) && NEAR_PINS.compose_hashes.includes(ch);
  checks.push({ name: `${p}app-id 和部署配置是固定的那一份`, status: pinned ? "PASS" : "FAIL",
                detail: `app-id ${appId ?? "缺失"}，compose-hash ${ch.slice(0, 16)}…` + (pinned ? "" : "，不在参考值里") });
  const cm = asObj(att.compose_manager_attestation);
  if (!cm) checks.push({ name: `${p}部署日志（compose-manager）`, status: "FAIL", detail: "缺少部署日志" });
  else {
    const cq = hexOrB64(cm.quote);
    const ctd = await tdxChecks(`${p}部署日志 · `, cq, args, now, checks, up.cm_collateral || null);
    trace.cm = cm;
    trace.cm_quote = bytesToHex(cq);
    checks.push(eqCheck(`${p}部署日志和模型在同一台机器（MRTD、RTMR0-3）`, regsOf(ctd), trace.regs));
    const ah = bytesToHex(await sha256(jcs(cm.actions || [])));
    const crd = bytesToHex(ctd.report_data);
    checks.push({ name: `${p}部署日志哈希绑定在 quote 里`, status: ah === cm.actions_hash && crd.slice(0, 64) === ah && crd.slice(64) === nonce ? "PASS" : "FAIL",
                  detail: `sha256(JCS(actions)) ${ah.slice(0, 16)}…，${(cm.actions || []).length} 条动作，随机数${crd.slice(64) === nonce ? "是本次的" : "不对"}` });
    const ups = (cm.actions || []).filter((a) => a.action === "compose_up");
    const last = ups[ups.length - 1] || {};
    trace.deploys = ups;
    checks.push({ name: `${p}模型代码由 compose-manager 运行时部署，不在硬件度量里`, status: "WARN",
                  detail: `${ups.length} 次部署 · 最近 ${last.tag ?? "?"} @ ${(last.commit || "?").slice(0, 7)} · ${last.file ?? "?"} · ${last.timestamp ?? ""}` });
  }
  const nv = asObj(att.nvidia_payload) || {};
  checks.push(eqCheck(`${p}GPU 证据用的是本次随机数`, String(nv.nonce || "").toLowerCase(), nonce));
  trace.nras = await gpuChecks(p, up.nras, nonce, null, now, checks);
  if (out.error || typeof out.reply !== "string") {
    checks.push({ name: `${p}加密发送`, status: "FAIL", detail: out.error || "没有回复" });
    return { checks, trace };
  }
  checks.push({ name: `${p}加密发送，只有这台模型机能解开`, status: "PASS",
                detail: "XChaCha20-Poly1305 第 3 版 · 消息、工具定义、工具调用逐字段加密 · 网关可见模型名、参数和消息条数" });
  const reqBytes = b64ToBytes(up.request_b64);
  const respBytes = b64ToBytes(up.response_b64);
  trace.request = { text: new TextDecoder().decode(reqBytes), sha256: bytesToHex(await sha256(reqBytes)) };
  trace.response = { text: new TextDecoder().decode(respBytes), sha256: bytesToHex(await sha256(respBytes)) };
  if (args.agent) {
    checks.push({ name: `${p}agent 发给模型的请求`, status: "INFO", detail: `${up.plain_messages ?? "?"} 条消息 · 逐字段加密` });
  } else checks.push(eqCheck(`${p}CVM 发出的就是我的消息`, up.plain_messages ?? null, out._messages));
  const sig = up.signature;
  trace.signature = sig || null;
  if (!sig) {
    checks.push({ name: `${p}回复签名（模型机密钥）`, status: "FAIL", detail: "没取到签名" });
    return { checks, trace };
  }
  const parts = String(sig.text || "").split(":");
  const [reqHash, respHash] = parts.slice(-2);
  let valid = false;
  try {
    const k = await subtle.importKey("raw", hexToBytes(String(sig.signing_address).replace(/^0x/, "")), { name: "Ed25519" }, false, ["verify"]);
    valid = await subtle.verify({ name: "Ed25519" }, k, hexOrB64(sig.signature), enc.encode(sig.text));
  } catch { valid = false; }
  const signer = String(sig.signing_address || "").replace(/^0x/, "").toLowerCase() === key;
  const kind = sig.signature_kind === "provider_tee";
  const model = parts.length === 3 && parts[0] === out.model;
  checks.push({ name: `${p}回复签名（模型机密钥）`, status: valid && signer && kind && model ? "PASS" : "FAIL",
                detail: `${valid ? "Ed25519 签名有效" : "签名无效"}；签名者${signer ? "是" : "不是"}刚验证的模型公钥；类型 ${sig.signature_kind ?? "未标注"}` +
                        `${kind ? "（模型机 TEE 签名）" : "（不是模型机签的）"}；签名里的模型 ${parts.length === 3 ? parts[0] : "缺失"}${model ? "" : "，和请求的不一致"}` });
  checks.push({ name: `${p}签名覆盖的请求 = CVM 发出的字节`, status: reqHash === trace.request.sha256 ? "PASS" : "FAIL",
                detail: "请求哈希由 NEAR 网关提供" });
  checks.push({ name: `${p}签名覆盖的回复 = CVM 收到的字节`, status: respHash === trace.response.sha256 ? "PASS" : "FAIL",
                detail: respHash === trace.response.sha256 ? "" : "回复被改写过" });
  return { checks, trace };
}

export async function tamperDemo(report, nonce, res, args) {
  const firstFail = async (rep, n, needle) => {
    const r = await verifyReport(rep, n, { quoteVerifier: args.quoteVerifier, collateral: res.collateral, requireCompose: true });
    return r.checks.find((c) => c.status === "FAIL" && c.name.includes(needle)) || null;
  };
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const r1 = clone(report);
  r1.attestation.evidence.app_compose = (r1.attestation.evidence.app_compose || "").replace("@sha256:", "@sha256:0", 1) + " ";
  const r3 = clone(report);
  const oldKey = r3.attestation.workload_keyset.e2ee_public_keys[0].public_key;
  const newKey = randomHex(32);
  r3.attestation.workload_keyset.e2ee_public_keys[0].public_key = newKey;
  delete r3.workload_keyset_digest;
  const r4 = clone(report);
  const q = hexToBytes(r4.attestation.evidence.quote);
  const before = q[200];
  q[200] ^= 0x01;
  r4.attestation.evidence.quote = bytesToHex(q);
  const replayNonce = randomHex(32);
  const byte = (b) => "0x" + b.toString(16).padStart(2, "0");
  const cases = [
    ["把部署配置改一个字（换镜像）", r1, nonce, "部署配置", [["app_compose", "第一个 @sha256: 改为 @sha256:0，末尾加一个空格"]]],
    ["拿旧证明冒充（换一个 nonce 验证）", report, replayNonce, "绑定", [["原 nonce", nonce], ["验证用 nonce", replayNonce]]],
    ["中间人换掉加密公钥", r3, nonce, "绑定", [["原公钥", oldKey], ["替换为", newKey]]],
    ["改 quote 里一个比特（伪造硬件证明）", r4, nonce, "硬件证明", [["quote[200]", `${byte(before)} → ${byte(q[200])}`]]],
  ];
  const rows = [];
  for (const [title, rep, n, needle, change] of cases) {
    const hit = await firstFail(rep, n, needle);
    rows.push({ name: title, status: hit ? "PASS" : "FAIL", detail: hit ? `被拦下：${hit.name}` : "没被发现！", change, hit });
  }
  return rows;
}

function pyDumps(v) {
  if (v === null || v === undefined) return "null";
  if (Array.isArray(v)) return "[" + v.map(pyDumps).join(", ") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).map((k) => JSON.stringify(k) + ": " + pyDumps(v[k])).join(", ") + "}";
  return JSON.stringify(v);
}

function infoChecks(m) {
  if (!("mr_td" in m)) return [];
  return [
    { name: "app_id", status: "INFO", detail: String(m.app_id ?? "None") },
    { name: "compose_hash（和发布记录比对）", status: "INFO", detail: String(m.compose_hash ?? "None") },
    { name: "系统镜像 os_image_hash（官方发布包）", status: "INFO", detail: `${m.image ?? "None"}：${m.os_image_hash ?? "None"}` },
    { name: "密钥来源（key-provider）", status: "INFO", detail: String(m.key_provider ?? "None") },
    { name: "app-compose 设置", status: "INFO", detail: pyDumps(m.app_compose_settings ?? null) },
    { name: "MRTD / RTMR0-2（固件、虚拟硬件、内核、rootfs，已和参考值比对）", status: "INFO",
      detail: `MRTD  ${m.mr_td}\nRTMR0 ${m.rtmr0}\nRTMR1 ${m.rtmr1}\nRTMR2 ${m.rtmr2}\nRTMR3 ${m.rtmr3}` },
  ];
}

export function bytesToB64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export async function* agentStream(base, res, inner, token, extra = {}) {
  const key = findE2eeKey(res.keyset);
  if (key === null) throw new Error("证明里没有本 MVP 的加密公钥");
  const ch = await ClientChannel.create(key, res.keyset_digest);
  const gatewayNonce = randomHex(32);
  const body = { ...inner, gateway_nonce: gatewayNonce, sent_at: Date.now() / 1000 };
  if (token) body.access_token = token;
  if (extra.sessionId) body.session_id = extra.sessionId;
  if (extra.reverify) body.reverify = true;
  if (extra.knownNonces) extra.knownNonces.add(gatewayNonce);
  const reqPlain = enc.encode(JSON.stringify(body));
  const envelope = await ch.seal(reqPlain, true);
  let r;
  try {
    r = await fetch(`${base}/v1/chat/stream`, { method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" },
                                                 body: JSON.stringify(envelope) });
  } catch {
    throw new ServiceError("连接失败");
  }
  if (!r.ok) throw new ServiceError(`HTTP ${r.status}`);
  yield ["sent", { gatewayNonce }];
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  const plains = [];
  let done = null;
  let broken = null;
  for (;;) {
    const { value, done: end } = await reader.read();
    if (value) buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const block = buf.slice(0, i);
      buf = buf.slice(i + 2);
      const line = block.split("\n").find((l) => l.startsWith("data:"));
      if (!line) continue;
      const f = JSON.parse(line.slice(5));
      if (f.done) { done = f; continue; }
      if (f.seq !== plains.length) { broken = `第 ${plains.length} 帧缺失或乱序`; continue; }
      let pt;
      try { pt = await ch.openFrame(f); } catch { broken = `第 ${f.seq} 帧解密失败`; continue; }
      plains.push(pt);
      yield ["event", JSON.parse(new TextDecoder().decode(pt))];
    }
    if (end) break;
  }
  const joined = concat(...plains.flatMap((p, k) => (k ? [enc.encode("\n"), p] : [p])));
  const checks = [];
  checks.push({ name: "加密流：每帧单独加密，序号连续", status: !broken && done && done.frames === plains.length ? "PASS" : "FAIL",
                detail: broken || (!done ? "流在结尾回执之前中断" : `${plains.length} 帧 · AES-256-GCM`) });
  const receipt = (done && done.receipt_sealed && (await ch.openReceipt(done.receipt_sealed))) || {};
  checks.push(await verifyReceiptSignature(receipt, res.keyset, res.api_version));
  checks.push(eqCheck("CVM 回执：请求哈希 = 我发出的内容", receiptHash(receiptEvent(receipt, "request.received")), await sha256Tag(reqPlain)));
  checks.push(eqCheck("CVM 回执：流式回复哈希 = 我收到的全部帧", receiptHash(receiptEvent(receipt, "response.returned")), await sha256Tag(joined)));
  const shown = token ? { ...body, access_token: "*".repeat(8) } : body;
  shown.attachments = (shown.attachments || []).map((a) => ({ ...a, data: `${(a.data || "").length} 个 base64 字符`,
                                                              ...(a.thumb ? { thumb: `缩略图 ${a.thumb.length} 字符` } : {}) }));
  const trace = { server_key: key, client_public_key: bytesToHex(ch.clientPub), keyset_digest: res.keyset_digest, receipt,
                  request: { envelope: { ...envelope, ciphertext_b64: `${envelope.ciphertext_b64.length} 个 base64 字符` }, plain: shown,
                             size: reqPlain.length, sha256: await sha256Tag(reqPlain) },
                  response: { frames: plains.length, size: joined.length, sha256: await sha256Tag(joined) } };
  yield ["checks", { checks, trace, gatewayNonce }];
}

export async function* runAgent(base, args) {
  const t0 = Date.now() / 1000;
  let session = args.session || null;
  const all = [];
  const result = { url: base, verified_at: Math.floor(t0), agent: true, provider: args.provider, model: args.model };
  const context = { report: null, nonce: null, res: null, channel: null, gateway: null, upstream: null, fresh: false, session: null, agent: null };
  const extra = { sessionId: args.sessionId, reverify: Boolean(args.reverify), knownNonces: args.knownNonces };
  const inner = { agent: "turn", input: args.input, attachments: args.attachments || [], provider: args.provider, model: args.model,
                  ...(args.chat && args.chat !== "default" ? { chat: args.chat } : {}) };
  let blocked = false;
  let upstream = null;
  const outbound = [];
  let turnNonce = null;
  let streamed = false;
  for (let attempt = 0; attempt < 2 && !streamed && !blocked; attempt++) {
    let res, report, nonce;
    if (session) {
      ({ res, report, nonce } = session);
      const reuse = [{ name: "沿用本会话的 CVM 验证", status: "INFO",
                       detail: `#${session.recId} · ${new Date(session.verifiedAt * 1000).toLocaleTimeString("zh-CN", { hour12: false })}` +
                               ` · ${minutesAgo(session.verifiedAt, t0)} 分钟前` }];
      yield ["section", ["cvm", reuse]];
      context.session = { recId: session.recId, verifiedAt: session.verifiedAt };
      result.cvm = reuse;
    } else {
      yield ["stage", "cvm"];
      ({ res, report, nonce } = await verifyCvm(base, args));
      yield ["section", ["cvm", res.checks]];
      const info = infoChecks(res.measurements);
      if (info.length) yield ["section", ["info", info]];
      all.push(...res.checks);
      result.cvm = res.checks;
      context.fresh = true;
      if (res.failed.length) {
        blocked = true;
        yield ["blocked", "证明未通过，未发送"];
      }
    }
    Object.assign(context, { report, nonce, res });
    result.measurements = res.measurements;
    result.raw_attestation = report;
    if (blocked) break;
    yield ["stage", "channel"];
    try {
      for await (const [kind, data] of agentStream(base, res, inner, args.token, extra)) {
        if (kind === "sent") { turnNonce = data.gatewayNonce; streamed = true; }
        else if (kind === "event") {
          if (data.type === "upstream") upstream = data;
          if (data.type === "tool.started" && /^(web_|browser_)/.test(data.tool_name || "")) outbound.push(data);
          yield ["agent", data];
        } else if (kind === "checks") {
          context.channel = data.trace;
          yield ["section", ["channel", data.checks]];
          all.push(...data.checks);
          result.channel = data.checks;
        }
      }
    } catch (e) {
      if (session && !streamed && e instanceof ServiceError && e.message === "HTTP 400") {
        session = null;
        context.session = null;
        extra.reverify = true;
        yield ["renew", "CVM 公钥已变，重新验证"];
        continue;
      }
      throw e;
    }
  }
  if (streamed) {
    yield ["stage", "gateway"];
    const p = args.provider;
    const label = { phala: "网关 · ", chutes: "Chutes · ", near: "NEAR · " }[p];
    const checks = [];
    const stopped = Boolean(upstream && upstream.stopped);
    const found = upstream && upstream.evidence ? upstream.evidence[p] : null;
    const ev = stopped && found && found.error ? null : found;
    const calls = (upstream && upstream.calls) || [];
    if (!ev) checks.push({ name: `${label}模型机验证`, status: stopped ? "INFO" : "FAIL",
                           detail: stopped ? "这一轮已停止，没有完成的模型调用" : "本轮没有成功的模型调用" });
    else {
      const out = { ...ev, _gateway_nonce: turnNonce, _messages: null };
      const vargs = { ...args, agent: { text: args.input } };
      if (p === "phala") {
        const r = await verifyGateway(out, vargs);
        checks.push(...r.checks);
        context.gateway = { nonce: out.gateway_nonce || turnNonce, report: r.report, model: out.model ?? null, trace: r.trace };
      } else {
        const r = await (p === "chutes" ? verifyChutes : verifyNear)(out, vargs);
        checks.push(...r.checks);
        context.upstream = { provider: p, model: out.model ?? null, trace: r.trace };
      }
    }
    const proof = (c) => {
      const v = c.verified || {};
      if (c.provider === "phala") return `回执 ${v.receipt_id ?? "?"} 验签通过 · 哈希一致 · 上游会话 ${v.upstream_session ?? "?"}`;
      if (c.provider === "chutes") return `实例 ${String(v.instance_id ?? "?").slice(0, 8)}… · ${v.e2e ?? ""}` +
                                         (v.stream_chunks ? ` · ${v.stream_chunks} 块` : "");
      return `模型机签名有效 · ${String(v.signing_address ?? "?").slice(0, 12)}…`;
    };
    calls.forEach((c, i) => checks.push({ name: `${label}模型调用 #${i + 1}`,
      status: c.ok && c.verified ? "PASS" : c.ok ? "FAIL" : stopped || c.aux || calls.slice(i + 1).some((d) => d.ok) ? "WARN" : "FAIL",
      detail: `${c.provider}/${c.model}${c.aux ? " · 辅助调用" : ""} · ${c.reused ? "沿用验证" : "完整验证"} · ${c.seconds}s` +
              (c.ok && c.verified ? ` · ${proof(c)}` : c.ok ? " · 无核对结果" : "") +
              (c.tool_calls && c.tool_calls.length ? ` · 工具 ${c.tool_calls.join("、")}` : "") +
              (c.error ? ` · ${c.error}` + (calls.slice(i + 1).some((d) => d.ok) ? " · 已重试" : "") : "") }));
    if (upstream) checks.push(...netChecks(upstream, outbound, calls));
    context.agent = { calls, provider: p, model: args.model, outbound, egress: upstream ? upstream.egress || [] : [] };
    yield ["section", ["gateway", checks]];
    all.push(...checks);
    result.gateway = checks;
    result.upstream_evidence = upstream ? upstream.evidence : null;
  }
  const counts = { PASS: 0, WARN: 0, FAIL: 0 };
  for (const c of all) if (c.status in counts) counts[c.status]++;
  yield ["done", { counts, elapsed: Date.now() / 1000 - t0, result, blocked, context }];
}

export function netChecks(up, outbound, calls) {
  const egress = up.egress || [];
  const hosts = (list) => Object.entries(list.reduce((m, e) => ({ ...m, [e.host]: (m[e.host] || 0) + 1 }), {}))
    .map(([h, n]) => (n > 1 ? `${h} ×${n}` : h)).join("、");
  const out = [];
  if (!up.egress_port) {
    out.push({ name: "联网开关", status: "WARN", detail: "未启用外网出口，开关不生效" });
    return out;
  }
  const removed = [...new Set(calls.flatMap((c) => c.net_tools_removed || []))];
  const denied = egress.filter((e) => !e.allowed);
  const shared = Math.max(0, ...egress.map((e) => e.shared || 0));
  const others = shared > 1 ? ` · 同时有 ${shared} 个会话在运行，无法区分来源` : "";
  const changed = up.internet_now !== undefined && up.internet_now !== up.internet ? ` · 中途切换为${up.internet_now ? "开启" : "关闭"}` : "";
  const leaked = egress.filter((e) => e.allowed);
  if (up.internet === false && leaked.length) {
    out.push({ name: "联网开关：已关闭，CVM 出口拒绝外网连接", status: "FAIL",
               detail: `关闭期间放行 ${leaked.length} 次：${hosts(leaked)}` + changed + others });
  } else if (up.internet === false) {
    out.push({ name: "联网开关：已关闭，CVM 出口拒绝外网连接", status: changed ? "WARN" : "PASS",
               detail: `拒绝 ${denied.length} 次${denied.length ? `（${hosts(denied)}）` : ""}` +
                       (removed.length ? ` · 已移除 ${removed.join("、")}` : "") +
                       changed + others });
  } else {
    const allowed = egress.filter((e) => e.allowed);
    const tools = outbound.map((t) => `${t.tool_name} ${String(t.preview || "").slice(0, 100)}`);
    out.push(allowed.length
      ? { name: "agent 联网：这些请求离开了 TEE", status: "WARN",
          detail: `访问 ${hosts(allowed)}` + (tools.length ? ` · ${tools.join("；")}` : "") + changed + others }
      : { name: "联网开关：已开启", status: "INFO", detail: "无外网访问" + changed });
  }
  if (!up.isolated) {
    out.push({ name: "出口隔离", status: "WARN", detail: "本地调试：容器可以绕过出口直连外网" });
  }
  return out;
}

export async function* run(base, args) {
  const t0 = Date.now() / 1000;
  let session = !args.authOnly && args.session ? args.session : null;
  const result = { url: base, verified_at: Math.floor(t0) };
  const all = [];
  const context = { report: null, nonce: null, res: null, channel: null, gateway: null, upstream: null, fresh: false, session: null };
  const extra = { sessionId: args.sessionId, reverify: Boolean(args.reverify), knownNonces: args.knownNonces };
  const inner = args.authOnly ? { auth_only: true } : { messages: args.messages, provider: args.provider || "phala" };
  let blocked = false;
  let out = null;
  for (let attempt = 0; attempt < 2 && out === null && !blocked; attempt++) {
    let res, report, nonce;
    if (session) {
      ({ res, report, nonce } = session);
      const reuse = [{ name: "沿用本会话的 CVM 验证", status: "INFO",
                       detail: `#${session.recId} · ${new Date(session.verifiedAt * 1000).toLocaleTimeString("zh-CN", { hour12: false })}` +
                               ` · ${minutesAgo(session.verifiedAt, t0)} 分钟前` }];
      yield ["section", ["cvm", reuse]];
      context.session = { recId: session.recId, verifiedAt: session.verifiedAt };
      result.cvm = reuse;
      result.reused_session = session.recId;
    } else {
      yield ["stage", "cvm"];
      ({ res, report, nonce } = await verifyCvm(base, args));
      yield ["section", ["cvm", res.checks]];
      const info = infoChecks(res.measurements);
      if (info.length) yield ["section", ["info", info]];
      all.push(...res.checks);
      result.cvm = res.checks;
      context.fresh = true;
      if (res.failed.length) {
        blocked = true;
        yield ["blocked", "证明未通过，未发送"];
      }
    }
    Object.assign(context, { report, nonce, res });
    result.measurements = res.measurements;
    result.raw_attestation = report;
    if (blocked) break;
    yield ["stage", "channel"];
    let r;
    try {
      r = await chat(base, res, inner, args.token, extra);
    } catch (e) {
      if (session && e instanceof ServiceError && e.message === "HTTP 400") {
        session = null;
        context.session = null;
        extra.reverify = true;
        yield ["renew", "CVM 公钥已变，重新验证"];
        continue;
      }
      throw e;
    }
    context.channel = r.trace;
    yield ["section", ["channel", r.checks]];
    all.push(...r.checks);
    result.channel = r.checks;
    out = r.out;
    if (out === null) break;
  }
  if (out !== null) {
    if (args.authOnly) {
      yield ["auth", { ok: out.ok === true, mode: out.mode ?? null, error: out.error ?? null, providers: out.providers ?? null,
                        models: out.models ?? null, agent: out.agent === true }];
    } else {
      if (out.mode === "phala") {
        yield ["stage", "gateway"];
        const { checks: gchecks, report: gres, trace: gtrace } = await verifyGateway(out, args);
        context.gateway = { nonce: out.gateway_nonce || out._gateway_nonce, report: gres, model: out.model ?? null, trace: gtrace };
        yield ["section", ["gateway", gchecks]];
        all.push(...gchecks);
        result.gateway = gchecks;
        result.gateway_receipt = out.receipt ?? null;
      } else if (out.mode === "chutes" || out.mode === "near") {
        yield ["stage", "gateway"];
        const { checks: uchecks, trace: utrace } = await (out.mode === "chutes" ? verifyChutes : verifyNear)(out, args);
        context.upstream = { provider: out.mode, model: out.model ?? null, trace: utrace };
        yield ["section", ["gateway", uchecks]];
        all.push(...uchecks);
        result.gateway = uchecks;
        result.upstream_evidence = out.upstream ?? null;
        if (out.error) yield ["error", out.error];
      } else if (out.error) {
        yield ["error", out.error];
      }
      yield ["reply", { text: out.reply ?? null, mode: out.mode ?? null, model: out.model ?? null }];
      result.reply = out.reply ?? null;
      result.mode = out.mode ?? null;
      result.model = out.model ?? null;
    }
  }
  const counts = { PASS: 0, WARN: 0, FAIL: 0 };
  for (const c of all) if (c.status in counts) counts[c.status]++;
  yield ["done", { counts, elapsed: Date.now() / 1000 - t0, result, blocked, context }];
}
