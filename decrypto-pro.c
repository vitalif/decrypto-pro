// https://habrahabr.ru/post/275039/
// Требуется либо OpenSSL 1.0.x (ГОСТ в составе), либо https://github.com/gost-engine/engine
// Сборка:
// 1) apt-get install libengine-gost-openssl1.1
// 2) make

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include "gost_lcl.h"

#if OPENSSL_VERSION_NUMBER >= 0x10100000
#define fill_GOST2001_params fill_GOST_EC_params
#define gost2001_compute_public gost_ec_compute_public
#endif

/* Convert little-endian byte array into bignum */
BIGNUM *reverse32bn(char *b, BN_CTX *ctx)
{
    BIGNUM *res;
    char buf[32];
    BUF_reverse(buf, b, 32);
    res = BN_bin2bn(buf, 32, BN_CTX_get(ctx));
    OPENSSL_cleanse(buf, sizeof(buf));
    return res;
}

void xor_material(char *buf36, char *buf5C, char *src)
{
    int i;
    for(i = 0; i < 32; i++)
    {
        buf36[i] = src[i] ^ 0x36;
        buf5C[i] = src[i] ^ 0x5C;
    }
}

int make_pwd_key(char *result_key, char *start12, int start12_len, char *passw)
{
    int result;
    int i;
    char pincode4[1024];
    int pin_len;
    char current[32];
    char material36[32];
    char material5C[32];
    char hash_result[32];
    gost_hash_ctx ctx;
    init_gost_hash_ctx(&ctx, &GostR3411_94_CryptoProParamSet);
    memset(pincode4, 0, sizeof(pincode4));
    pin_len = strlen(passw);
    if (pin_len*4 > sizeof(pincode4)) { result = 1; goto err; }
    for(i = 0; i < pin_len; i++)
        pincode4[i*4] = passw[i];

    start_hash(&ctx);
    hash_block(&ctx, start12, start12_len);
    if (pin_len) 
        hash_block(&ctx, pincode4, pin_len * 4);
    finish_hash(&ctx, hash_result);

    memcpy(current, (char*)"DENEFH028.760246785.IUEFHWUIO.EF", 32);

    for(i = 0; i < (pin_len?2000:2); i++)
    {
        xor_material(material36, material5C, current);
        start_hash(&ctx);
        hash_block(&ctx, material36, 32);
        hash_block(&ctx, hash_result, 32);
        hash_block(&ctx, material5C, 32);
        hash_block(&ctx, hash_result, 32);
        finish_hash(&ctx, current);
    }

    xor_material(material36, material5C, current);

    start_hash(&ctx);
    hash_block(&ctx, material36, 32);
    hash_block(&ctx, start12, start12_len);
    hash_block(&ctx, material5C, 32);
    if (pin_len) 
        hash_block(&ctx, pincode4, pin_len * 4);
    finish_hash(&ctx, current);

    start_hash(&ctx);
    hash_block(&ctx, current, 32);
    finish_hash(&ctx, result_key);

    result = 0; //ok
err:
    return result;
}

BIGNUM *decode_primary_key(char *pwd_key, char *primary_key, BN_CTX *bn_ctx)
{
    BIGNUM *res;
    char buf[32];
    gost_ctx ctx;
    gost_init(&ctx, gost_cipher_list->sblock);
    gost_key(&ctx, pwd_key);
    gost_dec(&ctx, primary_key, buf, 4);
    res = reverse32bn(buf, bn_ctx);
    OPENSSL_cleanse(buf, sizeof(buf));
    return res;
}

BIGNUM *remove_mask_and_check_public(char *oid_param_set8, BIGNUM *key_with_mask, BIGNUM *mask, char *public8, BN_CTX *ctx)
{
    int result;
    EC_KEY *eckey = NULL;
    const EC_POINT *pubkey;
    const EC_GROUP *group;
    BIGNUM *X, *Y, *order, *raw_secret, *mask_inv;
    char outbuf[32], public_X[32];
    ASN1_OBJECT *obj;
    int nid;

    order = BN_CTX_get(ctx);
    mask_inv = BN_CTX_get(ctx);
    raw_secret = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    Y = BN_CTX_get(ctx);
    if (!order || !mask_inv || !raw_secret || !X || !Y) { result = 1; goto err; }

    obj = ASN1_OBJECT_create(0, oid_param_set8+1, *oid_param_set8, NULL, NULL);
    nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);

    if (!(eckey = EC_KEY_new())) { result = 1; goto err; }
    if (!fill_GOST2001_params(eckey, nid)) { result = 1; goto err; }
    if (!(group = EC_KEY_get0_group(eckey))) { result = 1; goto err; }
    if (!EC_GROUP_get_order(group, order, ctx)) { result = 1; goto err; }

    if (!BN_mod_inverse(mask_inv, mask, order, ctx)) { result = 1; goto err; }
    if (!BN_mod_mul(raw_secret, key_with_mask, mask_inv, order, ctx)) { result = 1; goto err; }

    if (!EC_KEY_set_private_key(eckey, raw_secret)) { result = 1; goto err; }
    if (!gost2001_compute_public(eckey)) { result = 1; goto err; }
    if (!(pubkey = EC_KEY_get0_public_key(eckey))) { result = 1; goto err; }
    if (!EC_POINT_get_affine_coordinates_GFp(group, pubkey, X, Y, ctx)) { result = 1; goto err; }

    store_bignum(X, outbuf, sizeof(outbuf));
    BUF_reverse(public_X, outbuf, sizeof(outbuf));
    if (memcmp(public_X, public8, 8) != 0) { result = 1; goto err; }

    result = 0; //ok
err:
    if (eckey) EC_KEY_free(eckey);
    if (result == 0) return raw_secret;
    return NULL;
}

int file_length(char *fname)
{
    int len;
    FILE *f = fopen(fname, "rb");
    if (f == NULL) return -1;
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fclose(f);
    return len;
}

int read_file(char *fname, int start_pos, char *buf, int len)
{
    int read_len;
    FILE *f = fopen(fname, "rb");
    if (f == NULL) return 1;
    if (start_pos) fseek(f, start_pos, SEEK_SET);
    read_len = fread(buf, 1, len, f);
    fclose(f);
    if (read_len != len) return 1;
    return 0; //ok
}

int get_asn1_len(unsigned char *buf, int *size_hdr)
{
    int n, i, res;
    int pos = 0;
    if ((buf[pos]&0x80) == 0) {
        *size_hdr = 1;
        return buf[pos];
    }
    n = buf[pos++]&0x7f;
    res = 0;
    for(i = 0; i < n; i++) {
        res = res*256 + buf[pos++];
    }
    *size_hdr = n+1;
    return res;
}

#define MAX_HEADER 20000
int read_container(char *fpath, int flag2, char *salt12, char *primary_key, char *masks_key, char *public8, char *oid_param_set8)
{
    int result;
    char primary_path[1024+30];
    char masks_path[1024+30];
    char header_path[1024+30];
    char header_buf[MAX_HEADER];
    int header_len;
    int i, len, pos, size_hdr;

    if (strlen(fpath)>1024) { result = 1; goto err; }

    sprintf(header_path, "%s/header.key", fpath);
    if (flag2 == 0)
    {
        sprintf(primary_path, "%s/primary.key", fpath);
        sprintf(masks_path, "%s/masks.key", fpath);
    }
    else
    {
        sprintf(primary_path, "%s/primary2.key", fpath);
        sprintf(masks_path, "%s/masks2.key", fpath);
    }

    if (read_file(primary_path, 4, primary_key, 32)) { result = 1; goto err; }
    if (read_file(masks_path, 4, masks_key, 32)) { result = 1; goto err; }
    if (read_file(masks_path, 0x26, salt12, 12)) { result = 1; goto err; }

    header_len = file_length(header_path);
    if (header_len < 0x42 || header_len > MAX_HEADER) { result = 1; goto err; }
    if (read_file(header_path, 0, header_buf, header_len)) { result = 1; goto err; }

//------------- skip certificate ---------------------------
    pos = 0;
    for(i = 0; i < 2; i++)
    {
        get_asn1_len(header_buf+pos+1, &size_hdr);
        pos += size_hdr+1;
        if (pos > header_len-8) { result = 2; goto err; }
    }

//------------------ get oid_param_set8 -----------------------
#define PARAM_SET_POS 34
    if (memcmp(header_buf+pos+PARAM_SET_POS, "\x6\x7", 2) != 0) { result = 2; goto err; }
    memcpy(oid_param_set8, header_buf+pos+PARAM_SET_POS+1, 8);

//------------------ get public8 -----------------------
    result = 2; //not found
    pos += 52;
    for(i = 0; i < 3; i++)
    {
        len = get_asn1_len(header_buf+pos+1, &size_hdr);
        if (len == 8 && memcmp(header_buf+pos, "\x8a\x8", 2) == 0)
        {
            memcpy(public8,header_buf+pos+2,8);
            result = 0; //ok
            break;
        }
        pos += len+size_hdr+1;
        if (pos > header_len-8) { result = 2; goto err; }
    }
err:
    OPENSSL_cleanse(header_buf, sizeof(header_buf));
    return result;
}

#define START_OID 0x12
#define START_KEY 0x28
unsigned char asn1_private_key[72] = {
    0x30,0x46,2,1,0,0x30,0x1c,6,6,0x2a,0x85,3,2,2,0x13,0x30,0x12,6,7,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,6,7,0x2a,0x85,3,2,2,0x1e,1,4,0x23,2,0x21,0
};

int main(int argc, char **argv)
{
    int result;
    char *container_path;
    char *passw;
    char salt12[12];
    char primary_key[32];
    char masks_key[32];
    char public8[8];
    char oid_param_set8[8];
    BN_CTX *ctx;
    BIGNUM *key_with_mask;
    BIGNUM *mask;
    BIGNUM *raw_key;
    char pwd_key[32];
    char outbuf[32];

    ctx = BN_CTX_new();

    if (argc == 2)
    {
        container_path = argv[1];
        passw = "";
    }
    else
    if (argc == 3)
    {
        container_path = argv[1];
        passw = argv[2];
    }
    else
    {
        printf("get_private container_path [passw]\n");
        result = 1;
        goto err;
    }

    if (read_container(container_path, 0, salt12, primary_key, masks_key, public8, oid_param_set8) != 0 &&
        read_container(container_path, 1, salt12, primary_key, masks_key, public8, oid_param_set8) != 0)
    {
        printf("can not read container from %s\n", container_path);
        result = 2;
        goto err;
    }

    make_pwd_key(pwd_key, salt12, 12, passw);
    key_with_mask = decode_primary_key(pwd_key, primary_key, ctx);
    OPENSSL_cleanse(pwd_key, sizeof(pwd_key));
    mask = reverse32bn(masks_key, ctx);
    raw_key = remove_mask_and_check_public(oid_param_set8, key_with_mask, mask, public8, ctx);

    if (raw_key)
    {
        BIO *bio;
        store_bignum(raw_key, outbuf, sizeof(outbuf));
        memcpy(asn1_private_key+START_OID, oid_param_set8, 8);
        memcpy(asn1_private_key+START_KEY, outbuf, 32);
        //bio = BIO_new_file("private.key", "w");
        bio = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
        PEM_write_bio(bio, "PRIVATE KEY", "", asn1_private_key, sizeof(asn1_private_key));
        BIO_free(bio);
        OPENSSL_cleanse(outbuf, sizeof(outbuf));
        OPENSSL_cleanse(asn1_private_key, sizeof(asn1_private_key));
        result = 0; //ok
    }
    else
    {
        printf("Error check public key\n");
        result = 3;
    }

err:
    BN_CTX_free(ctx);
    OPENSSL_cleanse(salt12, sizeof(salt12));
    OPENSSL_cleanse(primary_key, sizeof(primary_key));
    OPENSSL_cleanse(masks_key, sizeof(masks_key));
    return result;
}
