// gcc -o proxy proxy.c -ltepla -lssl -lgmp -lcrypto -std=c99

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <sys/time.h>
#include <tepla/ec.h>
#include <openssl/sha.h>

#define DEBUG 0 // 0: false 1: true
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
void data_check(const int data, const int assumption);
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

int main(void) {
    /* --- セットアップ --- */
    int i;
//    char msg[MESSAGE_SIZE]="Hello World!";
    char msg[MESSAGE_SIZE]="abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";
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

    /* -- g := e(P, Q)を生成 --- */
    Element g;
    element_init(g, p->g3);
    pairing_map(g, P, Q, p);
    element_print(g);
    data_check(point_is_on_curve(P) + point_is_on_curve(Q), 2);

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
    memcpy(enc_msg,msg,strlen(msg));
    for(i=0;i<strlen(msg)/sizeof(long)+1;i++){
        printf("enc[%d]:%ld\n",i,enc_msg[i]);
    }
    //encode(g_key)
    memcpy(enc_key,g_key,strlen(msg));
    for(i=0;i<strlen(msg)/sizeof(long)+1;i++){
        printf("enc[%d]:%ld\n",i,enc_key[i]);
    }
    
    
//    unsigned char m[]  = "Hello_World!";
//    Element z;
//    element_init(z, p->g3);
//    element_from_oct(z, m, sizeof(m));
////    print_green_color("z = ");
//    element_print(z);
//    unsigned char os[sizeof(m)];
//    size_t size;
//    element_to_oct(os, &size, z);
//    print_unsigned_char(os, "test", size);

    /* --- 領域の解放 --- */
    point_clear(P);
    point_clear(Q);
    element_clear(g);
    pairing_clear(p);
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



