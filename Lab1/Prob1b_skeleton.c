#include<stdio.h>
#include<string.h>
#include <stdlib.h>

/* Caesar Decryption */
char* CaesarDecrypt(int, char*);
/* BruteForceAttack */
void BruteForceAttack(char*, char*); 

int main(){
 
  char ciphertext[1024];  
  char keyword[1024];

  /*
    Input ciphertext and keyword. 
    If keyword is not specified (no keyword), press ENTER
  */
  printf("Input the ciphertext: ");
  scanf("%[^\n]", ciphertext);
  while (getchar() != '\n');

  printf("Input the keyword: ");
  scanf("%[^\n]", keyword);
  while (getchar() != '\n');
  
  BruteForceAttack(ciphertext, keyword);
  return 0;

}

char* CaesarDecrypt(int key, char *ciphertext){
	char c;
	for(int i = 0; ciphertext[i] != '\0'; ++i){
		c = ciphertext[i];
		
		if(c >= 'a' && c <= 'z'){
			
			ciphertext[i] = (c + 26 - key - 97) % 26 + 97;
		}
		else if(c >= 'A' && c <= 'Z'){
	
			ciphertext[i] = (c + 26 - key - 65) % 26 + 65;
		}
	}
	return ciphertext;
}

void BruteForceAttack(char *ciphertext, char *keyword){
	char decrypttext[1024];
	for(int i = 0; i < 26; i++) {
		strcpy(decrypttext, CaesarDecrypt(i, ciphertext));
		if(keyword[0] == '\0'){
			printf("Key: %d\n", i);
			printf("The decryption message: %s\n", decrypttext);
		}else{
			if(strstr(decrypttext, keyword) != NULL){
				printf("Key: %d\n", i);
				printf("The decryption message: %s\n", decrypttext);
				return;
			}
			else if( i == 25)
				printf("There is no decryption for this keyword: %s\n", keyword);
		}
	}
}
