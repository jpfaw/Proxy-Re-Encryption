// gcc -o proxy proxy.c -ltepla -lssl -lgmp -lcrypto -std=c99

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <sys/time.h>
#include <tepla/ec.h>

#define DEBUG 0 // 0: false 1: true
#define MESSAGE_SIZE 1024
#define CODE_SIZE MESSAGE_SIZE/sizeof(long)

void print_red_color(const char *text);
void print_green_color(const char *text);
void create_mpz_t_random(mpz_t op, const mpz_t n);

int main(void) {
/* --- セットアップ --- */
    int i;
//    char msg[MESSAGE_SIZE]="Hello World!";
    char msg[MESSAGE_SIZE]="abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";
    int msg_len = strlen(msg);
    int roop_num = msg_len/sizeof(long) + 1;

/* --- 暗号化 --- */
    
    /* --- ペアリングを生成 --- */
    EC_PAIRING p;
    pairing_init(p, "ECBN254a");
    
    /* --- 上限値の設定 --- */
    mpz_t limit;
    mpz_init(limit);
    mpz_set(limit, *curve_get_order(p->g1));
    print_green_color("limit = "); gmp_printf ("%Zd\n", limit);
    
    /* --- 楕円曲線 E 上の点 P の生成 --- */
    EC_POINT P;
    point_init(P, p->g1);
    point_random(P);
    print_green_color("P =  "); point_print(P);
    
    /* --- 楕円曲線 E 上の点 Q の生成 --- */
    EC_POINT Q;
    point_init(Q, p->g2);
    point_random(Q);
    print_green_color("Q =  "); point_print(Q);
    
    /* --- aとrを生成 --- */
    mpz_t a, r;
    mpz_init(a);
    mpz_init(r);
    create_mpz_t_random(a, limit);
    create_mpz_t_random(r, limit);

    /* -- g = e(P, Q)^r を生成 --- */
    Element g;
    element_init(g, p->g3);
    pairing_map(g, P, Q, p);
    element_pow(g, g, r);       // r乗する
    print_green_color("g =  "); element_print(g);

    int element_size = element_get_str_length(g);
    char *g_element_str;
    if((g_element_str = (char *)malloc(element_size+1)) == NULL){
        printf("メモリが確保できませんでした。\n");
        return 0;
    }
    element_get_str(g_element_str, g);

    print_green_color("g_element_str_length = "); printf("%d\n", element_size);
    print_green_color("g_element_str = ");  printf("%s\n", g_element_str);

    /* --- g_element_strを12分割 --- */
    char g_key[12][65]={0}, *ptr;
    ptr = strtok(g_element_str, " ");
    strcpy(g_key[0], ptr);
    i=1;
    while(ptr != NULL) {
        ptr = strtok(NULL, " ");
        if(ptr != NULL) strcpy(g_key[i], ptr);
        i++;
    }
    if(DEBUG) for(i=0; i<12; i++) printf("%s\n", g_key[i]);
    
    /* --- 文字列を数値に変換 --- */
    //init
    unsigned long enc_msg[CODE_SIZE];
    memset(enc_msg,0,sizeof(enc_msg));
    unsigned long enc_key[CODE_SIZE];
    memset(enc_key,0,sizeof(enc_key));
    //encode(msg)
    memcpy(enc_msg,msg,msg_len);
    if(DEBUG) for(i=0;i<roop_num;i++) printf("enc_msg[%d]:%ld\n",i,enc_msg[i]);
    //encode(g_key)
    memcpy(enc_key,g_key,msg_len);
    if(DEBUG) for(i=0;i<roop_num;i++) printf("enc_key[%d]:%ld\n",i,enc_key[i]);

    /* --- 文字列と鍵を掛け算 --- */
    mpz_t u[roop_num];
    for(i=0;i<roop_num;i++) mpz_init(u[i]);
    for(i=0;i<roop_num;i++) {
        mpz_t a, b;
        mpz_init(a);
        mpz_init(b);
        mpz_set_ui(a, enc_msg[i]); // unsigned long -> mpz_t
        mpz_set_ui(b, enc_key[i%12]);
        mpz_mul(u[i], a, b); // mpz_t * mpz_t
        if(DEBUG) gmp_printf ("u[%d]: %Zd\n", i, u[i]);
        mpz_clears(a, b, NULL);
    }
    
    /* --- r(aQ) を計算 --- */
    EC_POINT raQ;
    point_init(raQ, p->g2);
    point_mul(raQ, a, Q);
    point_mul(raQ, r, raQ);
    print_green_color("raQ = "); point_print(raQ);
    
/* --- 復号 --- */
    
    /* --- 1/a --- */
    mpz_t a_one;
    mpz_init(a_one);
    mpz_invert(a_one, a, limit);

    /* --- (1/a)P --- */
    EC_POINT a1P;
    point_init(a1P, p->g1);
    point_mul(a1P, a_one, P);

    /* --- g2 = e((1/a)P, raQ) = e(P, Q)^r --- */
    Element g2;
    element_init(g2, p->g3);
    pairing_map(g2, a1P, raQ, p);
    if(DEBUG) {print_green_color("g2 = "); element_print(g2);}
    if(DEBUG) if(element_cmp(g, g2) == 0) print_green_color("g2CHECK: OK\n");
              else{print_green_color("g2CHECK: "); print_red_color("NG\n");};

    int element_g2_size = element_get_str_length(g2);
    char *g2_element_str;
    if((g2_element_str = (char *)malloc(element_g2_size+1)) == NULL) {
        printf("メモリが確保できませんでした。\n");
        return 0;
    }
    element_get_str(g2_element_str, g2);
    
    print_green_color("g2_element_str_length = "); printf("%d\n", element_g2_size);
    print_green_color("g2_element_str = "); printf("%s\n", g2_element_str);

    /* --- g2_element_strを12分割 --- */
    char g2_key[12][65]={0};
    ptr = strtok(g2_element_str, " ");
    strcpy(g2_key[0], ptr);
    i=1;
    while(ptr != NULL) {
        ptr = strtok(NULL, " ");
        if(ptr != NULL) strcpy(g2_key[i], ptr);
        i++;
    }
    if(DEBUG) for(i=0; i<12; i++) printf("%s\n", g2_key[i]);
    
    /* --- 文字列を数値に変換 --- */
    //init
    unsigned long enc_key2[CODE_SIZE];
    memset(enc_key2,0,sizeof(enc_key2));
    //encode(g2_key)
    memcpy(enc_key2,g2_key,msg_len);
    if(DEBUG) for(i=0;i<roop_num;i++) printf("enc_key2[%d]:%ld\n",i,enc_key2[i]);
    
    /* --- 文字列と鍵を割り算 --- */
    mpz_t dec_msg[msg_len];
    for(i=0;i<roop_num;i++) mpz_init(dec_msg[i]);
    for(i=0;i<roop_num;i++) {
        mpz_t a;
        mpz_init(a);
        mpz_set_ui(a, enc_key2[i%12]);
        mpz_divexact(dec_msg[i], u[i], a); // mpz_t / mpz_t
        if(DEBUG) gmp_printf ("dec_msg[%d]: %Zd\n", i, dec_msg[i]);
        mpz_clears(a, NULL);
    }

    unsigned long dec_msg_long[CODE_SIZE];
    for(i=0;i<roop_num;i++) dec_msg_long[i] = mpz_get_ui(dec_msg[i]);

    /* --- decode --- */
    char msg_decode[CODE_SIZE];
    memset(msg_decode,0,sizeof(msg_decode));
    memcpy(msg_decode,dec_msg_long,strlen(msg));
    print_green_color("message = "); printf("%s\n", msg_decode);

/* --- 領域の解放 --- */
    free(g_element_str);
    free(g2_element_str);
    for(i=0;i<roop_num;i++) mpz_clear(u[i]);
    for(i=0;i<roop_num;i++) mpz_clear(dec_msg[i]);
    mpz_clears(limit, a, r,a_one, dec_msg, NULL);
    point_clear(P);
    point_clear(Q);
    point_clear(raQ);
    point_clear(a1P);
    element_clear(g);
    element_clear(g2);
    pairing_clear(p);

    print_green_color("--- 正常終了 ---\n");
}


/* -----------------------------------------------
 * mpz_tでランダムな値を生成する関数
 * $0 生成した値を入れる変数
 * $1 上限値
 * 参考サイト https://sehermitage.web.fc2.com/etc/gmp_src.html
 -----------------------------------------------*/
void create_mpz_t_random(mpz_t op, const mpz_t n) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    
    struct timeval tv, tv2;
    gettimeofday(&tv2, NULL);
    
    do {
        gettimeofday(&tv, NULL);
    } while (tv.tv_usec == tv2.tv_usec);
    
    gmp_randseed_ui(state, tv.tv_usec);
    mpz_urandomm(op, state, n);
    
    gmp_randclear(state);
}

/* -----------------------------------------------
 * 文字列を緑色で出力する関数
 * $0 出力したい文字列
 -----------------------------------------------*/
void print_green_color(const char *text) {
    printf("\x1b[32m%s\x1b[39m", text);
}

/* -----------------------------------------------
 * 文字列を赤色で出力する関数
 * $0 出力したい文字列
 -----------------------------------------------*/
void print_red_color(const char *text) {
    printf("\x1b[31m%s\x1b[39m", text);
}



