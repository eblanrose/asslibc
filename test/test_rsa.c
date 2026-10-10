#include "test/utest.h"
#include "asslibc.h"
#include <string.h>
#include <stdlib.h>

static const char *k_p =
"f5b25944e4870317f07ffa2e1266f4c78e0cea7596d79812a2eeac3ed54fdd5eab0baa69cb4cd751c82dcac0a80d5839b0935efbe28b955df3a7a0bd95881cc1890eda7f75817371be629ad6b5f53782cf65dd3f98df00095d6dae048df927668b1bb2109d3174032116a760580f9d46bc4453b7181a35f010cdae2bde1b1c5b";

static const char *k_q =
"8b4a1d12e9029947a244d9fbf7b4f52ac3652ae8250f45c20bb3e64597ad366dded73dd42490bb65334ea68c010df092f624b5ae18e558d9554d9b4ce77c5e68162c73631041d68cfcbf69f9750d3997c5e0ea0493f917034bc84cf04d5829de1c5d488298e810472ab82b7b9015854126606afece6e75828cba8565abd7e923";

static const char *k_n =
"85aef7ed90484430ff6f7a64f0355efb959c54a3df918351311436a8b760f1fdf12d4fb9b9182a162655e279e5f1c20d1a1c5c4b82bce8bb340e53a8beb402a49e4a96efc15c4166dbb006a5d39d89a51642afc698fe08e1cd1d68d1d94f419b72b45f4a894c67cf3916f59e3b45949ce0add200c37f1b7cf8b97bb03f27d69ac175ffe71cdf9fcd7a4401dc7b481966d9d5636e3e380345d9fa685c9c45d0bd29a79269a2ac62fbf4367eefc1b4bd3dd07fa7d1ba3cdd751a4c72cb454c3335b835c7d24d578013a0b026a3c423ff6ad5f4fa2366c174d76877705322845a09de0a6f2662284bf14eb7b1d98b6e3cb78cc517af6b51114f2863d8c2a3f0b371";

static const char *k_e =
"10001";

static const char *k_d =
"6c90291badfe6212807e21a1734984773f8a9359f9a78c43155e5afd2cdef7e6c84389e9439d922026c5bc844deec52e2ab43967c12674c2028657fe43d0a00cdbd7ab37cd89843b69d14bb4c363be7268df832bfef6de73b1455ee87c57d6e9cc7f1a9bc7605b357821631a3afc48b215ec530cf7b673b64baf25f97d7076e041f1f17a866d4d9fa54e2ce82aec3d259fd5358246b26b7bba3d3c96b1df9a40b71ed92b5fac808a628b85a39bc8933d8b365e14fae756c4970b0296108fddb1455fb442bb8b6b58110c1a0062ed534b6d1b8a88a9d910a824259e910fb52c3c2c1277df44fa43bd27a9c1ddad0b22ceee94126da01db64b222139c7e4599539";

static const char *k_dp =
"dca375c1054c2d3e014e9bf765b5295a4f39500f9b0f2ed48596b9fd8f07b26f02416e9ea4dff378d0c036947e15c5c5c0c9070241f64183667c813fdf19a5613358b064c7bc2154e2b89ffdf2d72c2b7f5e25aaa7f8928ad668d95de3b4fc69fcc0394eec2aedd8a58d376fb0850d22e98c9e750ce2f4cf09f7fad21019de83";

static const char *k_dq =
"a0fba75e93af4d385d72f5fd20ed23eda8a6e4502984dd3ac80bc3b7eaf56652d59a2efb60c765ce30de55deb9d9429297a915d1813490db9e9b73420ec8ced3bdcce20f3c5adb7d5720637accaddc426d90e4e7259e5dda915b8e90acd3988ffc7853b59cc3990ca772f3ce7b58640a48306778d75d12b32fb2e339fec22bd";

static const char *k_qi =
"31dd749563f9b36e4228cbdf64a9eca0c6aec38f1246b5e4b9b2ca4d2a3bf8fd9364dbe177c4d1683b307a415936027bd79b6e7c5c55eaa0b774986e7e38ded7c91a36734a191cbe208aeb19c562fb14cf3007e842ee67aa2f484fc38e3e776e5bae9023c5defaa3b319677ae26993b872d7e0dc5bb67b5ff19d8d6823aea1b2";

static void h2b(const char *h, uint8_t *o, size_t ml) {
    memset(o, 0, ml);
    size_t len = strlen(h);
    size_t n = (len + 1) / 2;
    if (n > ml) n = ml;
    size_t off = ml - n;
    if (len & 1) {
        unsigned v; sscanf(h, "%1x", &v); o[off] = (uint8_t)v;
        for (size_t i = 1; i < n; i++) {
            unsigned v; sscanf(h + 1 + (i-1)*2, "%2x", &v); o[off+i] = (uint8_t)v;
        }
    } else {
        for (size_t i = 0; i < n; i++) {
            unsigned v; sscanf(h + i*2, "%2x", &v); o[off+i] = (uint8_t)v;
        }
    }
}

static void setup_key(assl_rsa_key *k) {
    assl_rsa_init(k);
    assl_bn n, e, d, p, q, dp, dq, qi;
    assl_bn_init(&n); assl_bn_init(&e); assl_bn_init(&d);
    assl_bn_init(&p); assl_bn_init(&q);
    assl_bn_init(&dp); assl_bn_init(&dq); assl_bn_init(&qi);
    assl_bn_from_hex(&n, k_n); assl_bn_from_hex(&e, k_e); assl_bn_from_hex(&d, k_d);
    assl_bn_from_hex(&p, k_p); assl_bn_from_hex(&q, k_q);
    assl_bn_from_hex(&dp, k_dp); assl_bn_from_hex(&dq, k_dq); assl_bn_from_hex(&qi, k_qi);
    assl_rsa_set_key(k, &n, &e, &d, &p, &q, &dp, &dq, &qi);
    assl_bn_free(&n); assl_bn_free(&e); assl_bn_free(&d);
    assl_bn_free(&p); assl_bn_free(&q);
    assl_bn_free(&dp); assl_bn_free(&dq); assl_bn_free(&qi);
}
static int fail = 0;

static int test_bn_rsa_raw(void) {
    utest_begin("rsa-raw");
    assl_rsa_key k; setup_key(&k);
    { uint8_t msg[256], ct[256], out[256];
      h2b("7e800d6569fa1b4d0ce7c497a6b09c3b41dfb69a11db93c36cf2af81492cb4243e23af875e8f644c8ef8dc1bcc6ae98431ea2a2c06d6dd579f00942eba9cc52d1f69f901f7b317e788f9a0b2aa756808e9b9d4e2feca80d852d873359e3e23d926e0c090ad4d89de5fa9ec0e24d4a54d93674afe6793ff4794ccf797d2b9e979e99cad48a79fe4ebd95d89a12e7081e296d6bf5750f258611a793e7080eb8491bdae1703842957d88923bc564561f377b37339e1955b0d51ff5f576dff0ecf0b0f23f019de087055655c490aca48d5f5396344cc656b991e2aba9538473cc9ac3525658ed7cb5b3fb4b531a29747e249d1bd9e3d4042dfcde60c214163e80932", msg, 256); h2b("60e7b2be4fb966ac36c7d0283a90d7829c953e96687159d454344acbc21c832efb6e8862f4d4821ec5bcdf76023b8cad0d4441490ef1285e9530f8e2a531ea69fcdbfc3bc21de80234d52bee37c7a25d460d05fff66f190c759152ec52af6ae5eda891d3a81b72ad915cce89b84e2de1d9ff952254417dc6729a39edb953d3114b7f16d4d9c9059acd16223807dc772e2a3b78187d2f8474b984c7d4383ed7e7395a21040c7f6b156166a42c185bdd4b300c6319c181df50be20b7ec443a7ba206b2621b392676b72edba4cdd38c7440a6989ba9f87477202f4823e2e0e4eb7285966f8c5e973e5294094722157266ae899390dcc6527973758af1170b50cf29", ct, 256);
      assl_rsa_public(&k, msg, 256, out);
      utest_bool(memcmp(out, ct, 256) == 0, "public"); }
    { uint8_t ct[256], pt[256], msg[256];
      h2b("60e7b2be4fb966ac36c7d0283a90d7829c953e96687159d454344acbc21c832efb6e8862f4d4821ec5bcdf76023b8cad0d4441490ef1285e9530f8e2a531ea69fcdbfc3bc21de80234d52bee37c7a25d460d05fff66f190c759152ec52af6ae5eda891d3a81b72ad915cce89b84e2de1d9ff952254417dc6729a39edb953d3114b7f16d4d9c9059acd16223807dc772e2a3b78187d2f8474b984c7d4383ed7e7395a21040c7f6b156166a42c185bdd4b300c6319c181df50be20b7ec443a7ba206b2621b392676b72edba4cdd38c7440a6989ba9f87477202f4823e2e0e4eb7285966f8c5e973e5294094722157266ae899390dcc6527973758af1170b50cf29", ct, 256); h2b("7e800d6569fa1b4d0ce7c497a6b09c3b41dfb69a11db93c36cf2af81492cb4243e23af875e8f644c8ef8dc1bcc6ae98431ea2a2c06d6dd579f00942eba9cc52d1f69f901f7b317e788f9a0b2aa756808e9b9d4e2feca80d852d873359e3e23d926e0c090ad4d89de5fa9ec0e24d4a54d93674afe6793ff4794ccf797d2b9e979e99cad48a79fe4ebd95d89a12e7081e296d6bf5750f258611a793e7080eb8491bdae1703842957d88923bc564561f377b37339e1955b0d51ff5f576dff0ecf0b0f23f019de087055655c490aca48d5f5396344cc656b991e2aba9538473cc9ac3525658ed7cb5b3fb4b531a29747e249d1bd9e3d4042dfcde60c214163e80932", msg, 256);
      assl_rsa_private(&k, ct, 256, pt);
      utest_bool(memcmp(pt, msg, 256) == 0, "private"); }
    { uint8_t ct[256], pt[256], msg[256];
      h2b("60e7b2be4fb966ac36c7d0283a90d7829c953e96687159d454344acbc21c832efb6e8862f4d4821ec5bcdf76023b8cad0d4441490ef1285e9530f8e2a531ea69fcdbfc3bc21de80234d52bee37c7a25d460d05fff66f190c759152ec52af6ae5eda891d3a81b72ad915cce89b84e2de1d9ff952254417dc6729a39edb953d3114b7f16d4d9c9059acd16223807dc772e2a3b78187d2f8474b984c7d4383ed7e7395a21040c7f6b156166a42c185bdd4b300c6319c181df50be20b7ec443a7ba206b2621b392676b72edba4cdd38c7440a6989ba9f87477202f4823e2e0e4eb7285966f8c5e973e5294094722157266ae899390dcc6527973758af1170b50cf29", ct, 256); h2b("7e800d6569fa1b4d0ce7c497a6b09c3b41dfb69a11db93c36cf2af81492cb4243e23af875e8f644c8ef8dc1bcc6ae98431ea2a2c06d6dd579f00942eba9cc52d1f69f901f7b317e788f9a0b2aa756808e9b9d4e2feca80d852d873359e3e23d926e0c090ad4d89de5fa9ec0e24d4a54d93674afe6793ff4794ccf797d2b9e979e99cad48a79fe4ebd95d89a12e7081e296d6bf5750f258611a793e7080eb8491bdae1703842957d88923bc564561f377b37339e1955b0d51ff5f576dff0ecf0b0f23f019de087055655c490aca48d5f5396344cc656b991e2aba9538473cc9ac3525658ed7cb5b3fb4b531a29747e249d1bd9e3d4042dfcde60c214163e80932", msg, 256);
      assl_rsa_private(&k, ct, 256, pt);
      utest_bool(memcmp(pt, msg, 256) == 0, "crt"); }
    assl_rsa_free(&k); return utest_end(); }

static int test_bn_rsa_pkcs1_enc(void) {
    utest_begin("rsa-pkcs1-enc");
    assl_rsa_key k; setup_key(&k);
    { uint8_t em[256], ct[256], out[256], pt[256], msg[64];
      h2b("0002088b1093189b20a328ab30b338bb40c348cb50d358db60e368eb70f378fb8005880d9015981da025a82db035b83dc045c84dd055d85de065e86df075f87d02850a8d12951a9d22a52aad32b53abd42c54acd52d55add62e56aed72f57afd82078a0f92179a1fa227aa2fb237ba3fc247ca4fd257da5fe267ea6ff277fa7f04870c8f14971c9f24a72caf34b73cbf44c74ccf54d75cdf64e76cef74f77c0184098c1194199c21a429ac31b439bc41c449cc51d459dc61e469ec71f479fc8106890e9116991ea126a92eb136b93ec146c94ed156d95ee166e96ef176f97e03860b8e13961b9e23a62b0048656c6c6f2052534120504b435323312076312e35", em, 256);
      h2b("5380b3e2d7b89f816fff8fb4885bdacb733f08caa6950bece20c9d17545383ecff1334952151092c7be948691d3f4f72ec03447d9229ca3a91951af2e57a11adf7b8a59103039395df4337085586194b61844f9ed5c981973445a71962b43b1b8815f857db9a2ecef7450bf2e56b8686a36d9230b42685e28feb7c7270ee1da534b952bb562d3223bafa9e4c48dc31e34dae0de0ac0e0c0fd3d1374c212949d44676e64a10e392de27e22503dc43c0534d6109f20e8719bb884ea8912bcf55c733ed4a13898acb742ef62b2635a6ec9b06614a1ae13ce8904767de6bfd50480f4704b95f193b110edde812f8b3b69e5938605150314522e465fc4ec2d82de60c", ct, 256);
      assl_rsa_public(&k, em, 256, out);
      utest_bool(memcmp(out, ct, 256) == 0, "encrypt_known_answer");
      assl_rsa_private(&k, ct, 256, pt);
      utest_bool(memcmp(pt, em, 256) == 0, "decrypt_known_answer");
      size_t mlen = 0;
      utest_bool(assl_rsa_decrypt(&k, ct, 256, msg, sizeof msg, &mlen) == 0, "decrypt_pkcs1_ok");
      utest_bool(mlen == 21 && memcmp(msg, "Hello RSA PKCS#1 v1.5", 21) == 0, "decrypt_message"); }
    { uint8_t ct[256], dec[256];
      const char *m = "roundtrip over the line";
      size_t mlen = strlen(m);
      size_t declen = 0;
      utest_bool(assl_rsa_encrypt(&k, (const uint8_t *)m, mlen, ct) == 0, "enc_ok");
      utest_bool(assl_rsa_decrypt(&k, ct, 256, dec, sizeof dec, &declen) == 0, "dec_ok");
      utest_bool(declen == mlen && memcmp(dec, m, mlen) == 0, "roundtrip"); }
    { uint8_t ct[256];
      const char *m = "x";
      size_t mlen = 1;
      assl_rsa_encrypt(&k, (const uint8_t *)m, mlen, ct);
      ct[0] ^= 1;
      uint8_t dec[256]; size_t declen = 0;
      utest_bool(assl_rsa_decrypt(&k, ct, 256, dec, sizeof dec, &declen) != 0, "reject_bad_ct");
      ct[0] ^= 1;
      ct[1] = 0x01;
      utest_bool(assl_rsa_decrypt(&k, ct, 256, dec, sizeof dec, &declen) != 0, "reject_bad_type"); }
    { uint8_t ct[256];
      const char *m = "z";
      assl_rsa_encrypt(&k, (const uint8_t *)m, 1, ct);
      uint8_t dec[256]; size_t declen = 0;
      utest_bool(assl_rsa_decrypt(&k, ct, 256, dec, sizeof dec, &declen) == 0, "ok_again"); }
    { uint8_t good[256];
      assl_rsa_encrypt(&k, (const uint8_t *)"0123456789abcdef0123456789abcdef"
                                  "0123456789abcdef", 40, good);
      uint8_t dec[256]; size_t dl = 0;
      int base_ok = assl_rsa_decrypt(&k, good, 256, dec, sizeof dec, &dl);
      utest_bool(base_ok == 0 && dl == 40, "baseline_conforming");

      uint8_t bad[256]; memcpy(bad, good, 256); bad[0] ^= 0xFF;
      dl = 0;
      utest_bool(assl_rsa_decrypt(&k, bad, 256, dec, sizeof dec, &dl) != 0,
                 "reject_wrong_block_type");
      memcpy(bad, good, 256); bad[0] = 0; bad[1] = 2; memset(bad + 2, 0xAA, 254);
      dl = 0;
      utest_bool(assl_rsa_decrypt(&k, bad, 256, dec, sizeof dec, &dl) != 0,
                 "reject_no_separator");
      memcpy(bad, good, 256); memset(bad + 2, 0x00, 4);
      dl = 0;
      utest_bool(assl_rsa_decrypt(&k, bad, 256, dec, sizeof dec, &dl) != 0,
                 "reject_short_padding");
      uint8_t other[256];
      assl_rsa_encrypt(&k, (const uint8_t *)"a different message entirely", 26, other);
      dl = 0;
      utest_bool(assl_rsa_decrypt(&k, other, 256, dec, sizeof dec, &dl) == 0 &&
                 dl == 26, "accept_other_conforming");

      uint8_t dirty[256];
      memset(dirty, 0xAB, sizeof dirty);
      dl = 0xDEAD;
      utest_bool(assl_rsa_decrypt(&k, bad, 256, dirty, sizeof dirty, &dl) != 0,
                 "malformed_again");
      int scrubbed = 1;
      for (size_t i = 0; i < sizeof dirty; i++) if (dirty[i] != 0) scrubbed = 0;
      utest_bool(scrubbed, "output_scrubbed_on_error");
      utest_bool(dl == 0, "outlen_zeroed_on_error"); }
    assl_rsa_free(&k); return utest_end(); }

static int test_bn_rsa_pkcs1_sign(void) {
    utest_begin("rsa-pkcs1-sign");
    assl_rsa_key k; setup_key(&k);
    { uint8_t dgst[20], sig[256];
      h2b("a9993e364706816aba3e25717850c26c9cd0d89d", dgst, 20);
      h2b("0e92182e88aae34615f45ff66699968eb9b9254eed4ff45892a083e99244b5411987b8b9481e0f9d5c0e80f718f573f6754bfa3b58cc0c279a59419e06ef2a27b6aa077c1bb160d8e5cd0ca3e3a8db94d0a00aa909188ed9768b90905684125f233097c4e90c52446b035827144f6529c3d3e2fb50122bbe1515b9d8c6417d9c739d97bc60811c149ddebe5b931493039729b68b867de15ce8ee557cd1f78fc6cc8dfe77cb8ac1f40f4035dc822e8146d58c5bfa94a67a12d3861095cdc21ec2c785c4aade26667899257885f241a84f22d4f1cdcfd3fabf2d4b5f936ecca94bbd513c50ffa27c80017be5354cd5314b3510f957befef789fea3b5f8005617c9", sig, 256);
      utest_bool(assl_rsa_verify(&k, ASSL_H_SHA1, dgst, sig, 256) == 0, "vfy_sha1"); }
    { uint8_t dgst[32], sig[256];
      h2b("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", dgst, 32);
      h2b("1c1c02c1f7a52c4fa09de6948e13ae77c001d9b36053b800b75923efdebcdf0127b80a668fda787fefcec47d5b12d668ff0799087e70371e51affea9e389068dee43889fee70441d69bc5fecf6331b4d3e00fad8cadda7d6d82a25e757cbcd5dc92fb389576352f56f4ecef1ede0999ff587f3f25284af149125f6e87090bdde2fcaf62f1a8368ed4d29949f2ed41979e25e982b89cb5d926088ebb2699d24ad79fe824ad59556c60dc69234e8c4bf2a41126ebdd86d4b9e07ce2bf29b6be7b5afc3f063c3162880616c9c1cea29e42af81f6fe4b3c9740643d5a6d5792c425f6b3d9546a50ae6ee58fc57f1eac9d86f8417b502cc7fac55aeb15a195e19cab4", sig, 256);
      utest_bool(assl_rsa_verify(&k, ASSL_H_SHA256, dgst, sig, 256) == 0, "vfy_sha256"); }
    { uint8_t dgst[48], sig[256];
      h2b("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", dgst, 48);
      h2b("5737cd06fcae026cedee95bdd622b7ed10d8ade0a0b1860fdd74b6a8e800f132101df1af660fd271ff9d007c3aa29b405eaa7ed8b521732db8550db23a32e2d996d9e7499288c634886db71b25f0216f7e9fde5af148c3951ed86e72682883542596ed150324a9d03cb69a4efee8058842ff9bbfa95df9d8eb38178e795ea10d2380b1c6a599b2d3de2d2a4737bdb12630195281616a6d81ecd4400d4555e12a7c753d8537c1d420d58449b25002825aa4f8d80c4cea83f7ba757ec28e4035b2b4a73b543320c99ef7eaa4c5af25fb605e9d374ba6fc1219c3928ec1666a7dcf649c4578c0a20ffecf36529cc996c5bcd191b7729c204b16c02dd5c4c6632d18", sig, 256);
      utest_bool(assl_rsa_verify(&k, ASSL_H_SHA384, dgst, sig, 256) == 0, "vfy_sha384"); }
    { uint8_t dgst[64], sig[256];
      h2b("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", dgst, 64);
      h2b("6370c644ea70645f3ae7814ea025813a0b735e03a26eee3f2b5971170dde318285b90c95bdc75db6b9e294ce7b17b605e79dc786409862c7684c61b70970b75deccee7d66be6ef274322bfaa8fe6ea8d85b5eeabc5784f0f473a0aef4a6e0256543b579c1d07304af22e789af0b84d19f9ad2ace46d781c05f3367901059f96fde0e197511f903d29b23ad6a1ed5a0f227e6ced735779569f485b10b0f3b6b3f1ddf69ee10073a632f61e7f56c1ca1c291926c14c34714f5fa0133df6b36c57adf9963fea423e5cf2b5ad47e0237f44087ef77ca0fc4610900e5f2e73879bf54ad11f8ac097afa19f5c3839779d45040e09ee2e208cb4701462a5c429dec2e13", sig, 256);
      utest_bool(assl_rsa_verify(&k, ASSL_H_SHA512, dgst, sig, 256) == 0, "vfy_sha512"); }
    { uint8_t dgst[32] = {0}, sig[256];
      dgst[0] = 0xff;
      utest_bool(assl_rsa_verify(&k, ASSL_H_SHA256, dgst, sig, 256) != 0, "bad_sig"); }
    assl_rsa_free(&k); return utest_end(); }

static int test_bn_rsa_pss(void) {
    utest_begin("rsa-pss");
    assl_rsa_key k; setup_key(&k);
    { uint8_t dgst[20], sig[256];
      h2b("a9993e364706816aba3e25717850c26c9cd0d89d", dgst, 20);
      h2b("835ce8318702f8be27d4a9114ff9895caaac8f5a15a86d7dc05514fef2e2f49f5b67aa1d3ed5370506ee1498364535418c6b42178ecfebc6f4d9635c26ed540944ccbe07c4d2353a1b1dee41db878942307cf8c82ba9d413c0d9cf5614b79b8a41581271050cd71ce7d86d73217bce60a69f91719cdc5732c837932c833a37ebe5c192a737d8a99f302dd447ab2909235e6b7aae9166cc3ba2239db807d80dea9cf1c1ddc94a2fba6337d2761c1a9fdfb1a8cee2117402fb4acf78ee51a596c5b94e5ac05a7f4de09a528282da4cd829d1070dbb7bfe520b2c61445ebf905ee90f590a4db818ec6b2301029b24565f5781283c3b4d9f866cddde5a58df86c6b3", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA1, dgst, 0, sig, 256) == 0, "vfy_sha1_0"); }
    { uint8_t dgst[20], sig[256];
      h2b("a9993e364706816aba3e25717850c26c9cd0d89d", dgst, 20);
      h2b("10aa1543ef5aa692b5fc6253f2ea2096c56ed98b275b1caeeb8428464ad196ce26ba29cf7c751969e0d344f4ef206be558a2fe1773427167d09d4eae2648f87ff3cae37688cc9f056c2808aef1fa3537cabfce5cc2bda02319a22948699a2064b535f9f39b1189fe01d6bfaa35f61cdd43f6389e1883bf675f91cdc62e20fbcaac3b2f064bc44449c718228c267e1ec1dff6e3672c345017ecea65658e5085d9774a1414e9dcc39fee3b2ebf4e7878e76e137a735ce8b0f927f22248b86b62c7d0655dff016eaeeb7443fe8b90a3e351c55ddaf05bd7414362281337ed19c00abe4c3f0812a5659a5072a89626d2a0bc43d1d5b04c6b6c5fb870f25a1a730ec3", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA1, dgst, 20, sig, 256) == 0, "vfy_sha1_20"); }
    { uint8_t dgst[20], sig[256];
      h2b("a9993e364706816aba3e25717850c26c9cd0d89d", dgst, 20);
      h2b("7af7e24dbaee7f9d8793d7f683c3a3ca60c78068c0e1093b40e71fe5aee9b67df263aab6e2c91792fe05000f8259be55d1e176604c8bcf13ee88d70442163b3a023397381f756cee01544b637f1b8689061c2f240b9f49d6285e4dbd3e793622281a4fde22016ec02aab9e7b8296af5018685ef9e4c1608478acae198f36099bcd19dce132b5744446f037fd6510e73c6f5aa616c960215b8bc5751d44f56186195d439d82f75cbc100b86f407ff60722823e577011e2415f635fde8f6a309d49bdddfb82baf30f05fe9c6342463f69ad980db47b9e269a58bd9e386f2a5c61251be21df0eb643dd4fcf865c9b07551500ca8440920738b56535cd4e4cbff9c3", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA1, dgst, 32, sig, 256) == 0, "vfy_sha1_32"); }
    { uint8_t dgst[20], sig[256];
      h2b("a9993e364706816aba3e25717850c26c9cd0d89d", dgst, 20);
      h2b("209f7af223c56fda5184de27487e044c7c75a5e0567bda95a400c9a50b12f4414bbd38fac2356afb86271d5cb0869e7c3d3d0d0743a20ec0013e425c3bae4cd280994fc7df7f4c70a87febbb1e1d1927302b44f61d16bda5512033a8a84552bfcedbd44d9da62a987c586f14e9618df490c4499bda5350b516a7fc443e55581838c9932c255a8a6dc9e806641d4dcc1f67c6caf9b9b504b78e878cdd05c6dd2017fbc021a84eefc91d0f485a64e0c64b2e6ec7dc5db00e84e9c28681dfd765114de884f1d4c00cb8a3ea397167a8f3f062aeb7008657e5e867e73ba35a979de0fa58b7acd7537189674ec1b76c8d91b24665fd405017db00247f94529919106f", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA1, dgst, 48, sig, 256) == 0, "vfy_sha1_48"); }
    { uint8_t dgst[32], sig[256];
      h2b("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", dgst, 32);
      h2b("1d9cb7712c64b5d062fcb163aa955a80212fa1cbf63283718883ad1151f3692b2e38b1582d0f332456a8586716d90981c0f1decea674abd1dfa86355c51b5e747f8d55b7468932f559b0699fa2d4b2b9890f3b8119e85b411391b5578a29e78cc73f554cae9b356ba64e34fc70cb77574f56869f8c436701c9a7a295bfb90c396d81547f07df1a9372b01c3e6179a31ff08b5b8bd321641f7897951957a2492637b3599057f2454d3fdac84a221326061390bec720b55b729062f07eef83836a4bd3fbd7f9569b55cc7a8f03d1cdd7966198e22e691d1404bd54e74212951100f144c84f1125c3ea55220f1d2bedf511cb7ac4c027b9438dec83752c779495f2", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA256, dgst, 0, sig, 256) == 0, "vfy_sha256_0"); }
    { uint8_t dgst[32], sig[256];
      h2b("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", dgst, 32);
      h2b("4a8e85bc1b241e464b8e9e4df9afaf9f998b4709c95d21d7e4fb8e8f945f5258df1079048c08eeb7f3387dc4ae38de032cb75763533a09331fda1ffd28caa5d55ba27a4ebedad989555bcb9b76d59d0e30c37da0010c12dcefcef4a084d03e4ba37c99b4818bdac435623ef02fef3df95c25f00979a11ab1e75e74259a82d1b556abfac26d93b029f750c138416a86f7859f851da6c073b147ad8f49cbfd38104c31908a2f50dcb1d175c332901b6b47d5e71f8fe66579ae93ab90d78fd060133f7b2c3ef22fec0f19544709b635feacb4fb425d9ec80c69dced8994869874306001046183bd962c20ba74aea892eeed333fc168b8188945de347071604dbe88", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA256, dgst, 20, sig, 256) == 0, "vfy_sha256_20"); }
    { uint8_t dgst[32], sig[256];
      h2b("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", dgst, 32);
      h2b("4df0005cffd887c71bdb704d33f53ede6057e6253a8f5b8183fb1180fb09f06333fcb6f5dc1fff441527a75960806da69d525b2de76a9c0c5abd31d5d1696fc217c0f5d845798863b811da1c6db796e006d23eba378971f253a11e55a129f53b9e4320d39a5ade15c3895e8faf62fdb7836b31999ac2d36abafa7a5341d9e746b4b200a209311958309227f2b36f55bd5b1a67ee66decd246349cdb7833905106b68d6a5478dea749315bf995dac967b2dd21dba4fd2580902524518ed99e4ea5a6aa0e869e22a7a85b5e160ab85ab6a86c946f1a0b38ff612aa7f43bf213961c5f897a21604643055ef829c6e803d0f9ee632f281ab38bd74ec9183c4c4e7a6", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA256, dgst, 32, sig, 256) == 0, "vfy_sha256_32"); }
    { uint8_t dgst[32], sig[256];
      h2b("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", dgst, 32);
      h2b("37ba8446fa3667fc1eef6ec9f95b718f1f5aac7925d39b3795a8e3af2c695770552bd5ce49743f8f062da34379a06f100b9525e79716883ae1a401429d9dc49212511ee047b31bac83a2b87be1288e9d3d3bc7d52d63977a5d1fd61068e002a9f22f3460a91dd2cc6475957a0a63e91d2200718d2b5308a4eebc22c8a4098b287376fa935371dee7b0f4f56ec31c9ad8cc6a40d494faf0a0c4b0c599dc273de7db813e326cf769af44f166d8affaca6b0b1823a8786eb34cbcca7bdf1809e8253708c1c9f56dfdcd2e2736d5b6053a314719e8f64c611977c66fb4c03da2d5040e035385dd4ec81dc5ec9340ea3218cc20ead9fd8af371e8148bd1e2f481ef6b", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA256, dgst, 48, sig, 256) == 0, "vfy_sha256_48"); }
    { uint8_t dgst[48], sig[256];
      h2b("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", dgst, 48);
      h2b("66b765cda8ef73116724ec079b64af1ab90d6859045d4220f5c573320db9a3aa8ff373dfd78cc2dee91e7522a4b17b7932325225f39032358997b3e2648fd0cbef28a3cd4265959a83160e125513f022c34c9d62af47bafc9c2eca62648581c2f3de65abc8e0f6953b981a2eeba6ea3952766954362cdc22f8b0e5e9bf9a92eaa013376d56994c59855c05ecddb01c06aa5fac1dc830f6020741548f64e2757e1f0e08f3fe57b95e0823f807de7b6bd1cacc5feabf912e14d73c726777e61a5dcfe7fe6df79c52c75844aad5ba7affee4ab178762d8cab7abb0a9b7cb3cbaae1fef11ff473fd85d626675568e030e42d247e52f40c5fa9163af317bf8c185734", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA384, dgst, 0, sig, 256) == 0, "vfy_sha384_0"); }
    { uint8_t dgst[48], sig[256];
      h2b("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", dgst, 48);
      h2b("51e03dfdf8fedd3f0955bb0a562c3b53aeeb1dbd1fff11acdbbc8c140f8d36c46ddb57c71015945d1f9957615b8e453d7e5b3c85c2d5bfdf5bbcbec4412971a2cbe5ce70f1c2730408511928b985f9c008c988c7ea89c23cf8e4779ac50e80d1d9217a37a2c5e18d60187ce6b84b9c7e5e4e189b256f75ad903f9cc3c581f4bf25db641c116a47b2ebcc22f2e4d5e3433295bcfa8fb34c333d5e90e45afdd8bc734e07f509ae94b0049bf7346369cdb7bf078cf918d41ee9fc2dc171948fba70bba77a18e4d23c6f2995c89c8600f8ff75e23b42341c25971c4aef9075cb9a993d8bf0a1dc7bd0670a1ce298b8a96678be7bf0ab03e7e3ddc43c690eff2f960d", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA384, dgst, 20, sig, 256) == 0, "vfy_sha384_20"); }
    { uint8_t dgst[48], sig[256];
      h2b("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", dgst, 48);
      h2b("233cfd0c5d8f56ea7168dc52eee69914a930e46a21f735cd27d8fae6722f452153b9abef127b57ff2775d55bd623fa5792dc2cb98d1c2d86fe1f9e3197e4aac16c42f45bbca11cd2048f07cbc64c008d96bd0c06c85827706d0e336140ee8beb963a0f9c037606f5e94820df0f0132d6a01076928ec73bb1233783698f2daffcf52b4043ccfe46f106243167f68b82f8c8212ca2ab89ca9d37260494f72884b87a7b518ca9adb8781799ee878a56da38e40f886ffc7e5fceb96c41986e9bb225119115a73e3eb01854e0b8e2684bc20b6691943c98caf6483ccc3dd1fe499f38bce05545b033ff5edecf94cea435e7f24f45892e427b08cf886e6a95861f6dbe", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA384, dgst, 32, sig, 256) == 0, "vfy_sha384_32"); }
    { uint8_t dgst[48], sig[256];
      h2b("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", dgst, 48);
      h2b("59de41305a2b8088f4706c03b61bb5be8311af815a48258460d5e459d66512775ee0a49f1c3becf66803d73dcc9cbbd762cb0097e0f7b7392850d863ef4615d2ba91a6cfba5ea5f585627ec22626583b216ee83afa8566a55efaf49be29518b4a9f11a9bd003bac326cffd269640aa8506f460102176f9afdbcc1255aeecaf0e56526db5c1df0991bbbafe1fa308d05e9a43d8aa7b19c656767851e522e05b7981ee608308301236889a7f72d75ffa2fd98b80f3eda0da74c1a0d76865b118c6ba97ccdcc62123e33b71c9a0fcd39e4facf67eafe40c93f0f936121608af5afe7ec6970dc6ee8060e1cf2d40693bec96e1dbc0bb86c09b88bc80c2fb69653c23", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA384, dgst, 48, sig, 256) == 0, "vfy_sha384_48"); }
    { uint8_t dgst[64], sig[256];
      h2b("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", dgst, 64);
      h2b("0464e47f311e04a589e874d978a19bef0d5e7a5bb86c789938f1d5fb3c81e85a0017f02325e03a771f77a3c1925722369bde2cab6c6ce0b239483fcb025045309b28e3ae5f1f34def9eb4873c68f31aa7e0d857a6c70a2020321af4b3dfc582e2ca321397e747bb20413841e0169dcc54ceff25a27ddaafa40686f6eceb9fda65ee584bebe6539308e19717da3325ee609dd47f94728b1b1d0259dd143771cf691b107a1b641cad60c9ef45a08e8eca3d409e51c561cde4a79f2b04c16cac412bf37c3c0ee6e8188893a039957e76ee910b9518b2659f4386c98c495e8c35c2abd7d2a1586403c2418644cc97d0c0b3790c296447cceccbffeb6d862523acffe", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA512, dgst, 0, sig, 256) == 0, "vfy_sha512_0"); }
    { uint8_t dgst[64], sig[256];
      h2b("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", dgst, 64);
      h2b("82b97ef78a148517f2fd8d10bc3459723418e60d5a31781b897d1da043567ffb0f2593fab3dd4ab929196710569463fdd5df1dea3b28bfa7af676e518facbd5bd4289108711b1b3f83cae0d505b78c4afca57e1260c0184e1f68aba034a38a50196d87ff5cdfa155639faeff70589f3c28e229c1f89eb7b3c0bfc602ee7d09aab1d6c2c42ca80ce8432a8ae6f99d0cccbedf03616bd94af7bb41cd86ae13d80402ee070423449d916b6a5a6a320c0b24865490a31cfbb0d940d0dd41fd0f35e9336743eae2672ff3b4130cb33bf026b4829be05d2eab4c200f622257bdbbb44fbed8ce22b90aaadc340e16e9bca402bb58f3ff39eecf25a6e48f895d9be7619b", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA512, dgst, 20, sig, 256) == 0, "vfy_sha512_20"); }
    { uint8_t dgst[64], sig[256];
      h2b("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", dgst, 64);
      h2b("79c691b8dbab0795ce3d842632fe4469a16415c18349ebf0474e5913b339c6107605c96b8b7579a90cc73b4ff26b4234f0de0e0f56ec3905815155d128e7fecf577332a65440c8caf324925d2a2d17d617a71460c985997de0521a2f16396538213c3395d2280acf96fa9145533b2168da84ea48e4dd24f1176ece887859901c9a68d38108bda7762cb39eec252750a64acfdf65a4cf8b15bd9d111666fb504b2b8c21978591f7eb2ef70602f685bc584c20dc3f05ed0db4bb52192ff51c3af077f8d327d7a7205347f49fcbc97a9cc85e1c5fbdbbffa55838e614d7f67404e716896e585517699293c3c946b168be841dd98a065cb370a549a5892127f51abe", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA512, dgst, 32, sig, 256) == 0, "vfy_sha512_32"); }
    { uint8_t dgst[64], sig[256];
      h2b("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", dgst, 64);
      h2b("759eacbe9df010fb9784579b1f18526f2efca07490c8ec0e6932452b45666e5598fb04d1f630e52b40de6d2518db31022c0d1005ddf3562b9892ca88ee53fc583268a7f5d529dcbca9825fa4539d793896da7c80eafe02ea146185e95f7feb3472018b5146cdf6a9587b0835ae782a2d4466c2b8c8962d434b479cafc2ab4b42932635d8ed4089ea0cf4110a2eefbddef208d27d5cceda63d43ee60279ac614a71e1c05e19caa39cc3fbcb95209b6044f37159ef81441111232f62b95851fbd337914316e3d475a6e357a67bcc6f4c9c1d93f78ce65ead5aab17a53e49fe9284cebf9d29e1522fabd31b800bd22d415fd4e2479fdc2a828709c78208a8e07978", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA512, dgst, 48, sig, 256) == 0, "vfy_sha512_48"); }
    { uint8_t dgst[20], sig[256];
      h2b("a9993e364706816aba3e25717850c26c9cd0d89d", dgst, 20);
      utest_bool(assl_rsa_sign_pss(&k, ASSL_H_SHA1, dgst, 20, sig) == 0, "rt_sign_sha1");
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA1, dgst, 20, sig, 256) == 0, "rt_vfy_sha1"); }
    { uint8_t dgst[32], sig[256];
      h2b("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", dgst, 32);
      utest_bool(assl_rsa_sign_pss(&k, ASSL_H_SHA256, dgst, 20, sig) == 0, "rt_sign_sha256");
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA256, dgst, 20, sig, 256) == 0, "rt_vfy_sha256"); }
    { uint8_t dgst[48], sig[256];
      h2b("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", dgst, 48);
      utest_bool(assl_rsa_sign_pss(&k, ASSL_H_SHA384, dgst, 20, sig) == 0, "rt_sign_sha384");
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA384, dgst, 20, sig, 256) == 0, "rt_vfy_sha384"); }
    { uint8_t dgst[64], sig[256];
      h2b("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", dgst, 64);
      utest_bool(assl_rsa_sign_pss(&k, ASSL_H_SHA512, dgst, 20, sig) == 0, "rt_sign_sha512");
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA512, dgst, 20, sig, 256) == 0, "rt_vfy_sha512"); }
    { uint8_t dgst[32], sig[256];
      h2b("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", dgst, 32);
      h2b("4a8e85bc1b241e464b8e9e4df9afaf9f998b4709c95d21d7e4fb8e8f945f5258df1079048c08eeb7f3387dc4ae38de032cb75763533a09331fda1ffd28caa5d55ba27a4ebedad989555bcb9b76d59d0e30c37da0010c12dcefcef4a084d03e4ba37c99b4818bdac435623ef02fef3df95c25f00979a11ab1e75e74259a82d1b556abfac26d93b029f750c138416a86f7859f851da6c073b147ad8f49cbfd38104c31908a2f50dcb1d175c332901b6b47d5e71f8fe66579ae93ab90d78fd060133f7b2c3ef22fec0f19544709b635feacb4fb425d9ec80c69dced8994869874306001046183bd962c20ba74aea892eeed333fc168b8188945de347071604dbe88", sig, 256);
      utest_bool(assl_rsa_verify_pss(&k, ASSL_H_SHA256, dgst, 10, sig, 256) != 0, "bad_saltlen"); }
    assl_rsa_free(&k); return utest_end(); }

int main(void) {
    fail += test_bn_rsa_raw();
    fail += test_bn_rsa_pkcs1_enc();
    fail += test_bn_rsa_pkcs1_sign();
    fail += test_bn_rsa_pss();
    if (fail) { fprintf(stderr, "FAIL: %d suites\n", fail); return 1; }
    fprintf(stderr, "ALL RSA CHECKS PASSED\n");
    return 0;
}
