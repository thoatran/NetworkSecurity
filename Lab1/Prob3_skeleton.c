#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include <ctype.h>

struct incidence_pair{         
  char c[26];                                        // Letter in the cipher text
  double freq[26];                                   // Incidence percentage of each letter
};
  
struct incidence_pair getIncidence(char*);           // Computing a histogram of the incidence each letter (ignoring all non alphabet characters)
char* monoalphabetic_substitution(char*, char*);     // Takes a partial mono-alphabetic substitution (subs)  and a ciphertext and returns a potential plaintext

int main(int argc, char *argv[]){
  
  char ciphertext[1024] = "ztmn pxtne cfa peqef kecnp cjt tmn zcwsenp ontmjsw ztnws tf wsvp xtfwvfefw, c feb fcwvtf, xtfxevqea vf gvoenwk, cfa aeavxcwea wt wse rntrtpvwvtf wscw cgg lef cne xnecwea eymcg.";
  char plaintext[1024] = "";
  char subs[1024] = "";
  int check = 0;

  struct incidence_pair ip = getIncidence(ciphertext);

  if(argc != 2){
    printf("Not enough or too many arguments!\n");
    exit(1);
  }
  //check the valid of the substitution input
  strcpy(subs, argv[1]);
  for(int i = 0; subs[i] != '\0'; i++){
    check = i + 1;
  }
  if(check != 26 && check != 0){
    printf("The substitution must be a 26-character string\n");
    exit(1);
  }

  //find the frequency of the characters in the ciphertext
  if(strcmp(subs, "") == 0){
    for(int i = 0; i < 26; i++)
      printf("%c:%5f\n", ip.c[i], ip.freq[i]);
    return 0;
  }

  strcpy(plaintext, monoalphabetic_substitution(ciphertext, subs));
  printf("Potential Plaintext: %s\n", plaintext);
  return 0;
}

struct incidence_pair getIncidence(char *ciphertext){
  struct incidence_pair tmp;
  for(int i = 0; i < 26; i++) {
    tmp.freq[i] = 0;
    tmp.c[i] = 'a' + i;
  }
  char c;
  int length = 0; // length of the ciphertext
  for(int i = 0; ciphertext[i] != '\0'; i++) {
    c = ciphertext[i];
    if(c >= 'a' && c <= 'z'){
      tmp.freq[c - 'a'] += 1;
      length += 1;
    }
  }
  // calculate the frequency of each character
  for(int i = 0; i < 26; i++) {
    tmp.freq[i] = tmp.freq[i] / (double)length;
  }

  //sort the incidence pair by the frequency of the characters 
  for(int i = 0; i < 26; i++) {
    for(int j = i + 1; j < 26; j++){
      if(tmp.freq[i] < tmp.freq[j]){
        double f = tmp.freq[i];
        tmp.freq[i] = tmp.freq[j];
        tmp.freq[j] = f;
        char ch = tmp.c[i];
        tmp.c[i] = tmp.c[j];
        tmp.c[j] = ch;
      }
    }
  }
  return tmp;
}

char* monoalphabetic_substitution(char *ciphertext, char *subs){
  for(int i = 0; ciphertext[i] != '\0'; i++) {
    ciphertext[i] = toupper(ciphertext[i]);
  }
  for(int i = 0; i < 26; i++) {
    if(subs[i] != '_'){
      for(int j = 0; ciphertext[j] != '\0'; j++) {
        if(ciphertext[j] == 'A' + i){
          ciphertext[j] = subs[i];
        } 
      }
    }
  }
  return ciphertext;
}
