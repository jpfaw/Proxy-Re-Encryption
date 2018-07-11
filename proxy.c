// gcc -o proxy proxy.c -ltepla -lssl -lgmp -lcrypto -std=c99

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <sys/time.h>
#include <tepla/ec.h>
#include <openssl/sha.h>

#define DEBUG 1 // 0: false 1: true
#define MESSAGE_SIZE 1024
#define CODE_SIZE MESSAGE_SIZE/sizeof(long)

typedef enum{
    ADD,
    SUB,
    AND,
    OR,
    XOR
}Mode;

void print_red_color(const char *text);
void print_green_color(const char *text);
void create_mpz_t_random(mpz_t op, const mpz_t n);
void data_check(const int data, const int assumption);
void print_unsigned_char(const unsigned char *uc, const char *dataName, const size_t size);

int main(void) {
/* --- セットアップ --- */
    int i;
//    char msg[MESSAGE_SIZE]="Hello World!";
    char msg[MESSAGE_SIZE]="abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";
    int msg_len = strlen(msg);
    
    /* --- 上限値の設定 --- */
    mpz_t limit;
    mpz_init(limit);
    mpz_set_ui(limit, 2);
    mpz_pow_ui(limit, limit, 254);
    print_green_color("limit = ");
    gmp_printf ("%s%Zd\n", "", limit);

/* --- 暗号化 --- */
    
    /* --- ペアリングを生成 --- */
    EC_PAIRING p;
    pairing_init(p, "ECBN254a");
    
    /* --- 楕円曲線 E 上の点 P の生成 --- */
    EC_POINT P;
    point_init(P, p->g1);
    point_random(P);
    print_green_color("P =  ");
    point_print(P);
    
    /* --- 楕円曲線 E 上の点 Q の生成 --- */
    EC_POINT Q;
    point_init(Q, p->g2);
    point_random(Q);
    print_green_color("Q =  ");
    point_print(Q);
    
    data_check(point_is_on_curve(P) + point_is_on_curve(Q), 2);
    
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
    element_print(g);

    int element_size = element_get_str_length(g);
    char *g_element_str;
    g_element_str = (char *)malloc(element_size+1);
    if(g_element_str == NULL) {
        printf("メモリが確保できませんでした。\n");
        return 0;
    }else{
        element_get_str(g_element_str, g);
        print_green_color("g_element_str_length = ");
        printf("%d\n", element_size);
        print_green_color("g_element_str = ");
        printf("%s\n", g_element_str);
    }
    
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
    if(DEBUG) for(i=0;i<msg_len/sizeof(long)+1;i++) printf("enc_msg[%d]:%ld\n",i,enc_msg[i]);
    //encode(g_key)
    memcpy(enc_key,g_key,msg_len);
    if(DEBUG) for(i=0;i<msg_len/sizeof(long)+1;i++) printf("enc_key[%d]:%ld\n",i,enc_key[i]);

    /* --- 文字列と鍵を掛け算 --- */
    mpz_t u[msg_len];
    for(i=0;i<msg_len/sizeof(long);i++) mpz_init(u[i]);
    for(i=0;i<msg_len/sizeof(long);i++) {
        mpz_t a, b;
        mpz_init(a);
        mpz_init(b);
        mpz_set_ui(a, enc_msg[i]); // unsigned long -> mpz_t
        mpz_set_ui(b, enc_key[i]);
        mpz_mul(u[i], a, b); // mpz_t * mpz_t
        if(DEBUG) gmp_printf ("u[%d]: %Zd\n", i, u[i]);
    }
    
    /* --- r(aQ) を計算 --- */
    EC_POINT aQ;
    EC_POINT raQ;
    point_init(aQ, p->g2);
    point_init(raQ, p->g2);
    point_mul(aQ, a, Q);
    point_mul(raQ, r, aQ);
    print_green_color("raQ = ");
    point_print(raQ);
    
/* --- 復号 --- */
    
    /* --- 1/a --- */
    unsigned long uOne = 1;
    mpz_t one;
    mpz_init(one);
    mpz_set_ui(one, uOne);
    mpz_t a_minutes_one;
    mpz_init(a_minutes_one);
//    mpz_divexact(a_minutes_one, one, a);
    mpz_t amari;
    mpz_init(amari);
    mpz_cdiv_qr(a_minutes_one, amari, one, a);
    gmp_printf ("a_minutes_one: %Zd\namari: %Zd\n", a_minutes_one, amari);

    /* --- 領域の解放 --- */
    free(g_element_str);
    mpz_clears(limit, a, r, NULL);
    for(i=0;i<msg_len/sizeof(long);i++) mpz_clear(u[i]);
    point_clear(P);
    point_clear(Q);
    point_clear(aQ);
    point_clear(raQ);
    element_clear(g);
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
 * unsigned char(SHA256でハッシュ化した値)を出力する関数
 * $0 出力するu_char
 * $1 データ名（出力の最初にprintされる）
 * $2 データサイズ
 -----------------------------------------------*/
void print_unsigned_char(const unsigned char *uc, const char *dataName, const size_t size){
    printf("\x1b[32m%s = \x1b[39m", dataName);
    for (size_t i=0; i<size; i++){
        printf("%02x", uc[i] );
    }
    printf("\n");
}

/* -----------------------------------------------
 * データをチェックする関数
 * $0 チェックしたいデータ
 * $1 理想の値
 -----------------------------------------------*/
void data_check(const int data, const int assumption) {
    if(data == assumption){
        print_green_color("CHECK: OK\n");
    } else {
        print_green_color("CHECK: ");
        print_red_color("NG\n");
    }
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



