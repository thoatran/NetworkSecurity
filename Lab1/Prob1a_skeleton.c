#include<stdio.h>
#include<string.h>
#include<stdlib.h>

/* Caesar Encryption */
char* CaesarEncrypt(int, char*);
/* Caesar Decryption */
char* CaesarDecrypt(int, char*);

int main(){
  char plaintext[1024];
  char ciphertext[1024];
  char decrypttext[1024];
  
  int key;

  /*
    Input plaintex and key.
    Check the validity of key (key must be an interger number between 0 ~ 25)
  */
  printf("Input the plaintext: ");
  scanf("%[^\n]", plaintext);
  while (getchar() != '\n');
  do{
  	printf("The key must be from 0 to 25\n");
  	printf("Input key: ");
  	scanf("%d", &key);
  } while(key < 0 || key > 25);

  /*
    Perform Caesar Encryption: CaesarEncrypt(key, plaintext) and print out the ciphertext
  */
  strcpy(ciphertext, CaesarEncrypt(key, plaintext));
  printf("Encrypted message: %s\n", ciphertext);
  
  /*
    Perform Caesar Decryption: CaesarDecrypt(key, ciphertext) and print out the decryted ciphertext (decrypttext)
  */
 	strcpy(decrypttext,CaesarDecrypt(key, ciphertext));
  	printf("Decrypted message: %s\n", decrypttext);
  	return 0;
}

char* CaesarEncrypt(int key, char *plaintext){
	char c;
	for(int i = 0; plaintext[i] != '\0'; i++){
		c = plaintext[i];
		if(c >= 'a' && c <= 'z'){

			plaintext[i] = (c + key - 97) % 26 + 97;
		}
		else if(c >= 'A' && c <= 'Z'){

			plaintext[i] = (c + key - 65) % 26 + 65;
		}
	}
	return plaintext;
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
