//2020 11-18
//compile: gcc liuy.c -lgmp -lpbc -lcrypto -o liuy
// Efficient Privacy-Preserving Dual Authentication and Key Agreement Scheme fo Secure V2V Communications in an IoV Paradigm
# include<pbc/pbc.h>
# include<pbc/pbc_test.h>
# include<openssl/sha.h>
# include<openssl/aes.h>
# include<string.h>
# include<stdlib.h>
# include<stdio.h>
# include<time.h>

# define HASH_LEN 20
# define MAXLEN 4096
# define MAX_PARAM 6

void h1(unsigned char* result, element_t *e1);
void h2(unsigned char* result, unsigned char* estr, int len);
void combine(unsigned char* result,  element_t* es[], int size);
int combine4_s(unsigned char* result, element_t* e1, unsigned char*c, int len, element_t* e3, element_t* e4);
int element_xor(unsigned char* result, unsigned char* str1, unsigned char* str2, int len);
void print_hex(unsigned char* ustr, int len);
void g(unsigned char* result, element_t* e1);

int main(int argc, char* argv[])
{
    pairing_t pairing;
    double time1, time2;
    int byte1, byte2;
    int len1, len2, len3, maxlen;
    int comm_traffic;


    element_t P, Ppub, Pr, Sr, rrPr, rrSr, IMi, IMj, sIMi, sIMj, IMit, Mti, Mtj, Mi, Mj, sigmai, sigmaj, G1temp1, G1temp2;
    element_t s, IDr, rr, IDi, IDj, PWi, PWj, xi, xj,  xiv, Ri, Rj, Zi, Zj, Ziv, TSregi, TSregj, AIDi, AIDj, TSi, TSj, TSt, TSr;
    element_t SKrk, k, ri, ki, SKir, riP, rjP, kr, MAC, MACt, TDi, TDj, SKij, Zntemp1, Zntemp2;
    element_t GTtemp1, GTtemp2;

    unsigned char hash_result[HASH_LEN];
    unsigned char ivec[16];
    unsigned char temp1[MAXLEN];
    unsigned char temp2[MAXLEN];
    unsigned char temp3[MAXLEN];

    element_t* params[MAX_PARAM];

    AES_KEY key;

    pbc_demo_pairing_init(pairing, argc, argv);

    if (!pairing_is_symmetric(pairing))
    {
        fprintf(stderr, "only works with symmetric pairing\n");
        exit(1);
    }
    comm_traffic = 0;

    element_init_G1(P, pairing);
    element_init_G1(Ppub, pairing);
    element_init_G1(Pr, pairing);
    element_init_G1(Sr, pairing);
    element_init_G1(rrPr, pairing);
    element_init_G1(rrSr, pairing);
    element_init_G1(riP, pairing);
    element_init_G1(rjP, pairing);
    element_init_G1(IMi, pairing);
    element_init_G1(sIMi, pairing);
    element_init_G1(IMj, pairing);
    element_init_G1(sIMj, pairing);
    element_init_G1(IMit, pairing);
    element_init_G1(Mti, pairing);
    element_init_G1(Mtj, pairing);
    element_init_G1(Mi, pairing);
    element_init_G1(Mj, pairing);
    element_init_G1(sigmai, pairing);
    element_init_G1(sigmaj, pairing);

    element_init_Zr(s, pairing);
    element_init_Zr(IDr, pairing);
    element_init_Zr(rr, pairing);
    element_init_Zr(IDi, pairing);
    element_init_Zr(IDj, pairing);
    element_init_Zr(PWi, pairing);
    element_init_Zr(PWj, pairing);
    element_init_Zr(xi, pairing);
    element_init_Zr(xj, pairing);
    element_init_Zr(xiv, pairing);
    element_init_Zr(Ri, pairing);
    element_init_Zr(Rj, pairing);
    element_init_Zr(Zi, pairing);
    element_init_Zr(Zj, pairing);
    element_init_Zr(Ziv, pairing);
    element_init_Zr(AIDi, pairing);
    element_init_Zr(AIDj, pairing);
    element_init_Zr(TSi, pairing);
    element_init_Zr(TSj, pairing);
    element_init_Zr(TSt, pairing);
    element_init_Zr(TSr, pairing);
    element_init_Zr(ri, pairing);
    element_init_Zr(ki, pairing);
    element_init_Zr(SKir, pairing);
    element_init_Zr(kr, pairing);
    element_init_Zr(SKrk, pairing);
    element_init_Zr(k, pairing);
    element_init_Zr(MAC, pairing);
    element_init_Zr(MACt, pairing);
    element_init_Zr(TDi, pairing);
    element_init_Zr(TDj, pairing);
    element_init_Zr(TSregi, pairing);
    element_init_Zr(TSregj, pairing);
    element_init_Zr(Zntemp1, pairing);
    element_init_Zr(Zntemp2, pairing);

    element_init_GT(GTtemp1, pairing);
    element_init_GT(GTtemp2, pairing);

    time1 = pbc_get_time();
    element_random(s);
    element_random(P);
    element_random(IDr);
    element_random(rr);

    element_mul_zn(Ppub, P, s);
    h1(hash_result, &IDr);
    element_from_hash(Pr, hash_result, HASH_LEN);
    element_mul_zn(Sr, Pr, s);
    element_mul_zn(rrPr, Pr, rr);
    element_mul_zn(rrSr, Sr, rr);

    time2 = pbc_get_time();
    printf("PKG init: %fs\n", time2 - time1);

    printf("Registration and Login......\n");
    time1 = pbc_get_time();

    // int i;
    // for (i = 0; i < 100; i++)
    // {
        element_random(IDi);
        element_random(IDj);
        element_random(PWi);
        element_random(PWj);
        element_random(xi);
        element_random(xj);
        element_random(TDi);
        element_random(TDj);
        element_random(k);

        //OBUi
        //element_printf("xi: %B\n", xi);
        len1 = element_length_in_bytes(IDi) + element_length_in_bytes(PWi);
        memset(temp1, 0, MAXLEN);
        params[0] = &IDi;
        params[1] = &PWi;
        combine(temp1, params, 2);
        h2(hash_result, temp1, len1);

        element_from_hash(Zntemp1, hash_result, HASH_LEN);
        memset(temp1, 0, MAXLEN);
        element_to_bytes(temp1, Zntemp1);

        len2 = element_length_in_bytes(xi);
        memset(temp2, 0, MAXLEN);
        element_to_bytes(temp2, xi);
        memset(temp3, 0, MAXLEN);
        len3 = element_xor(temp3, temp1, temp2, len1);   
        element_from_bytes(Ri, temp3);


        len1 = element_length_in_bytes(IDi) + element_length_in_bytes(PWi) + element_length_in_bytes(xi);
        memset(temp1, 0, MAXLEN);
        params[0] = &IDi;
        params[1] = &PWi;
        params[2] = &xi;
        combine(temp1, params, 3);
        h2(hash_result, temp1, len1);
        element_from_bytes(Zi, hash_result);

        element_random(TSregi);
        len1 = element_length_in_bytes(IDi) + element_length_in_bytes(xi) + element_length_in_bytes(TSregi);
        memset(temp1, 0, MAXLEN);
        params[0] = &IDi;
        params[1] = &xi;
        params[2] = &TSregi;
        combine(temp1, params, 3);
        h2(hash_result, temp1, len1);
        element_from_hash(IMi, hash_result, HASH_LEN);
        element_mul_zn(sIMi, IMi, s);

        //OBUj
        len1 = element_length_in_bytes(IDj) + element_length_in_bytes(PWj);
        memset(temp1, 0, MAXLEN);
        params[0] = &IDj;
        params[1] = &PWj;
        combine(temp1, params, 2);
        h2(hash_result, temp1, len1);
        element_from_hash(Zntemp1, hash_result, HASH_LEN);
        memset(temp1, 0, HASH_LEN);
        element_to_bytes(temp1, Zntemp1);

        len2 = element_length_in_bytes(xj);
        memset(temp2, 0, MAXLEN);
        element_to_bytes(temp2, xj);

        memset(temp3, 0, MAXLEN);
        len3 = element_xor(temp3, temp1,  temp2, len2);
        element_from_bytes(Rj, temp3);

        len1 = element_length_in_bytes(IDj) + element_length_in_bytes(PWj) + element_length_in_bytes(xj);
        memset(temp1, 0, MAXLEN);
        params[0] = &IDj;
        params[1] = &PWj;
        params[2] = &xj;
        combine(temp1, params, 3);
        h2(hash_result, temp1, len1);
        element_from_bytes(Zj, hash_result);

        element_random(TSregj);
        len1 = element_length_in_bytes(IDj) + element_length_in_bytes(xj) + element_length_in_bytes(TSregj);
        memset(temp1, 0, MAXLEN);
        params[0] = &IDj;
        params[1] = &xj;
        params[2] = &TSregj;
        combine(temp1, params, 3);
        h2(hash_result, temp1, len1);
        element_from_hash(IMj, hash_result, HASH_LEN);
        element_mul_zn(sIMj, IMj, s);
        

        //OBUi Login
        len1 = element_length_in_bytes(IDi) + element_length_in_bytes(PWi);
        memset(temp1, 0, MAXLEN);
        params[0] = &IDi;
        params[1] = &PWi;
        combine(temp1, params, 2);
        h2(hash_result, temp1, len1);
        element_from_hash(Zntemp1, hash_result, HASH_LEN);
        memset(temp1, 0, MAXLEN);
        element_to_bytes(temp1, Zntemp1);

        len2 = element_length_in_bytes(Ri);
        memset(temp2, 0, MAXLEN);
        element_to_bytes(temp2, Ri);

        memset(temp3, 0, MAXLEN);
        element_xor(temp3, temp2, temp1, len2);
        element_from_bytes(xiv, temp3);
        //element_printf("xiv: %B\n", xiv);

        len1 = element_length_in_bytes(IDi) + element_length_in_bytes(PWi) + element_length_in_bytes(xiv);
        memset(temp1, 0, MAXLEN);
        params[0] = &IDi;
        params[1] = &PWi;
        params[2] = &xiv;
        combine(temp1, params, 3);
        h2(hash_result, temp1, len1);
        element_from_bytes(Ziv, hash_result);

        // if (element_cmp(Zi, Ziv) == 0)
        //     printf("Accept!\n");
        // else
        //     printf("Reject!\n");
    // }



    time2 = pbc_get_time();
    printf("Extracton and login: %fs\n", time2 - time1);
    fprintf(stderr, "%0.2f, ", (time2 - time1) * 1000);


    printf("Key Agreement......\n");
    time1 = pbc_get_time();

    element_random(TSi);
    len1 = element_length_in_bytes(IMi) + element_length_in_bytes(TSi);
    memset(temp1, 0, MAXLEN);
    params[0] = &IMi;
    params[1] = &TSi;
    combine(temp1, params, 2);
    h2(hash_result, temp1, len1);
    element_from_bytes(AIDi, hash_result);

    element_random(TSj);
    len1 = element_length_in_bytes(IMj) + element_length_in_bytes(TSj);
    memset(temp1, 0, MAXLEN);
    params[0] = &IMj;
    params[1] = &TSj;
    combine(temp1, params, 2);
    h2(hash_result, temp1, len1);
    element_from_bytes(AIDj, hash_result);

    element_random(ri);
    element_pairing(GTtemp1, rrPr, Ppub);  
    element_pow_zn(GTtemp2, GTtemp1, ri);
    h1(hash_result, &GTtemp2);
    element_from_bytes(ki, hash_result);

    g(hash_result, &ki);
    element_from_bytes(SKir, hash_result);

    len1 = element_length_in_bytes(IDi) + element_length_in_bytes(Ppub) + element_length_in_bytes(IMi) + element_length_in_bytes(TSi);
    memset(temp1, 0, MAXLEN);
    memset(temp2, 0, MAXLEN);
    params[0] = &IDi;
    params[1] = &Ppub;
    params[2] = &IMi;
    params[3] = &TSi;
    combine(temp1, params, 4);


    AES_set_encrypt_key(hash_result, 128, &key);
    AES_cbc_encrypt(temp1, temp2, len1, &key, ivec, AES_ENCRYPT);
    comm_traffic += len1 + 16;

    element_random(TSr);
    element_mul_zn(riP, P, ri);
    element_pairing(GTtemp1, rrSr, riP);
    h1(hash_result, &GTtemp1);
    
    element_from_bytes(kr, hash_result);

    g(hash_result, &kr);
    element_from_bytes(SKrk, hash_result);
    AES_cbc_encrypt(temp2, temp1, len1 + 16, &key, ivec, AES_DECRYPT);


    len1 = element_length_in_bytes(IDi) + element_length_in_bytes(IMi) + element_length_in_bytes(AIDi)
        + element_length_in_bytes(IDj) + element_length_in_bytes(IMj) + element_length_in_bytes(AIDj);
    memset(temp1, 0, MAXLEN);
    memset(temp2, 0, MAXLEN);

    params[0] = &IDi;
    params[1] = &IMi;
    params[2] = &AIDi;
    params[3] = &IDj;
    params[4] = &IMj;
    params[5] = &AIDj;
    combine(temp1, params, 6);
    len3 = element_length_in_bytes(k);
    memset(temp3, 0, MAXLEN);
    element_to_bytes(temp3, k);

    AES_set_encrypt_key(temp3, 128, &key);
    AES_cbc_encrypt(temp1, temp2, len1, &key, ivec, AES_ENCRYPT);

    
    len3 = element_length_in_bytes(Pr) + len1 + 16 + element_length_in_bytes(TSr) + element_length_in_bytes(k);
    memset(temp3, 0, MAXLEN);
    combine4_s(temp3, &Pr, temp2, len1 + 16, &TSr, &k);
    h2(hash_result, temp3, len3);
    element_from_bytes(MAC, hash_result);

    element_random(TSt);
    len3 = element_length_in_bytes(Pr) + len1 + 16 + element_length_in_bytes(TSr) + element_length_in_bytes(k);
    memset(temp3, 0, MAXLEN);
    combine4_s(temp3, &Pr, temp2, len1 + 16, &TSr, &k);
    h2(hash_result, temp3, len3);
    element_from_bytes(MACt, hash_result);
    AES_cbc_encrypt(temp2, temp1, len1 + 16, &key, ivec, AES_DECRYPT);


    len1 = element_length_in_bytes(IDi) + element_length_in_bytes(xi) + element_length_in_bytes(TSregi);
    memset(temp1, 0, MAXLEN);
    params[0] = &IDi;
    params[1] = &xi;
    params[2] = &TSregi;
    combine(temp1, params, 3);
    h2(hash_result, temp1, len1);
    element_from_hash(IMit, hash_result, HASH_LEN);

    if (element_cmp(IMi, IMit) == 0)
        printf("Accept!\n");
    else
        printf("Reject!\n");
    
    
    len1 = element_length_in_bytes(AIDi) + element_length_in_bytes(TDi) + element_length_in_bytes(TSt);
    memset(temp1, 0, MAXLEN);
    params[0] = &AIDi;
    params[1] = &TDi;
    params[2] = &TSt;
    combine(temp1, params, 3);
    h2(hash_result, temp1, len1);
    element_from_hash(Mti, hash_result, HASH_LEN);
    element_mul_zn(sigmai, Mti, s);

    len1 = element_length_in_bytes(AIDj) + element_length_in_bytes(TDj) + element_length_in_bytes(TSt);
    memset(temp1, 0, MAXLEN);
    params[0] = &AIDj;
    params[1] = &TDj;
    params[2] = &TSt;
    combine(temp1, params, 3);
    h2(hash_result, temp1, len1);
    element_from_hash(Mtj, hash_result, HASH_LEN);
    element_mul_zn(sigmaj, Mtj, s);

    element_pairing(GTtemp1, P, sigmai);   
    element_pairing(GTtemp2, Ppub, Mti);
    
    if (element_cmp(GTtemp1, GTtemp2) == 0)
        printf("Accept!\n");
    else
        printf("Reject!\n");

    element_pairing(GTtemp1, P, sigmaj);
    element_pairing(GTtemp2, Ppub, Mtj);
    if (element_cmp(GTtemp1, GTtemp2) == 0)
        printf("Accept!\n");
    else
        printf("Reject!\n");

    len1 = element_length_in_bytes(AIDi) + element_length_in_bytes(TDi) + element_length_in_bytes(TSt);
    memset(temp1, 0, MAXLEN);
    params[0] = &AIDi;
    params[1] = &TDi;
    params[2] = &TSt;
    combine(temp1, params, 3);
    h2(hash_result, temp1, len1);
    element_from_hash(Mi, hash_result, HASH_LEN);
    element_mul_zn(sigmai, Mi, s);

    len1 = element_length_in_bytes(AIDj) + element_length_in_bytes(TDj) + element_length_in_bytes(TSt);
    memset(temp1, 0, MAXLEN);
    params[0] = &AIDj;
    params[1] = &TDj;
    params[2] = &TSt;
    combine(temp1, params, 3);
    h2(hash_result, temp1, len1);
    element_from_hash(Mj, hash_result, HASH_LEN);
    element_mul_zn(sigmaj, Mj, s);


    time2 = pbc_get_time();
    element_printf("ki: %B\n", ki);
    element_printf("kr: %B\n", kr);
    printf("Key agreement: %fs\n", time2 - time1);
    fprintf(stderr, "%0.2f\n", (time2 - time1) * 1000);
    comm_traffic += element_length_in_bytes(AIDi) + element_length_in_bytes(IDi) + element_length_in_bytes(TSi) + element_length_in_bytes(riP) + element_length_in_bytes(Ppub);
    comm_traffic += element_length_in_bytes(AIDj) + element_length_in_bytes(IDj) + element_length_in_bytes(TSj) + element_length_in_bytes(rjP) + element_length_in_bytes(Ppub);
    comm_traffic += element_length_in_bytes(AIDi) + element_length_in_bytes(AIDj) + element_length_in_bytes(MAC) + element_length_in_bytes(TSr) + element_length_in_bytes(Pr);
    comm_traffic += 3 * (element_length_in_bytes(AIDi) + element_length_in_bytes(AIDj) + element_length_in_bytes(TDi) + element_length_in_bytes(TDj) + element_length_in_bytes(TSt)
        +element_length_in_bytes(sigmai) + element_length_in_bytes(Mi));
    fprintf(stdout, "Communication traffic: %d\n", comm_traffic);
    fprintf(stdout, "Key memeory cost: %d\n", element_length_in_bytes(Pr) + element_length_in_bytes(Sr) + 2 * (element_length_in_bytes(PWi) + element_length_in_bytes(IMi) + element_length_in_bytes(sIMi)));

    return 0;
}


void h1(unsigned char* result, element_t *e1)
{
    int elelen;
    unsigned char* estr;
    elelen = element_length_in_bytes(*e1);

    estr = (unsigned char*)malloc(sizeof(unsigned char) * elelen);
    if (estr == NULL)
    {
        fprintf(stderr, "error!\n");
        exit(0);
    }
    element_snprintf(estr, elelen, "%B", *e1);
    SHA1((const unsigned char *)estr, strlen(estr),  result);
    free(estr);
}

void g(unsigned char* result, element_t* e1)
{
    h1(result, e1);
}

void h2(unsigned char* result, unsigned char* estr, int len)
{
    SHA1((const unsigned char *)estr, len, result);
}

void combine(unsigned char* result,  element_t* es[], int size)
{
    int i, len;
    unsigned char* ptr;

    ptr = result;
    for (i = 0; i < size; i++)
    {
        len = element_length_in_bytes(*es[i]);
        element_to_bytes(ptr, *es[i]);
        ptr += len;
    }
}


int combine4_s(unsigned char* result, element_t* e1, unsigned char*c, int len, element_t* e3, element_t* e4)
{
    int elen1, elen3, elen4;
    unsigned char* estr1, *estr3, *estr4;

    elen1 = element_length_in_bytes(*e1);
    elen3 = element_length_in_bytes(*e3);
    elen4 = element_length_in_bytes(*e4);

    estr1 = (unsigned char*)malloc(sizeof(unsigned char) * elen1);
    estr3 = (unsigned char*)malloc(sizeof(unsigned char) * elen3);
    estr4 = (unsigned char*)malloc(sizeof(unsigned char) * elen4);
    if (result == NULL || estr1 == NULL || estr3 == NULL || estr4 == NULL)
    {
        fprintf(stderr, "error!\n");
        exit(0);
    }
    element_snprintf(estr1, elen1, "%B", *e1);
    element_snprintf(estr3, elen3, "%B", *e3);
    element_snprintf(estr4, elen4, "%B", *e4);

    memcpy(result, estr1, elen1);
    memcpy(result + elen1, c, len);
    memcpy(result + elen1 + len, estr3, elen3);
    memcpy(result + elen1 + len + elen3, estr4, elen4);

    free(estr1);
    free(estr3);
    free(estr4);

    return elen1 + len + elen3 + elen3;
}

int element_xor(unsigned char* result, unsigned char* str1, unsigned char* str2, int len)
{
    int i;

    if (result == NULL)
        return -1;
    else
    {
        for (i = 0; i < len; i++)
            result[i] = str1[i] ^ str2[i];
    }
    return len;
}

void print_hex(unsigned char* ustr, int len)
{
    int i;
    for (i = 1; i < len; i++)
        printf("%x", ustr[i]);
    printf("\n");
}