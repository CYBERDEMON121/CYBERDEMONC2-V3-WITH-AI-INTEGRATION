#include <windows.h>
#include <stdio.h>

// Function to perform simple XOR encryption/decryption
void xor_encrypt_decrypt(char* input, char key) {
  char* iterator = input;
  while(*iterator) {
    *iterator ^= key;
    iterator++;
  }
}

int main(){
  char payload[] = "<MY_MALICIOUS_PAYLOAD>";
  printf("Original Payload: %s\n", payload);

  // Encrypt the payload
  xor_encrypt_decrypt(payload, 'K');
  printf("Encrypted Payload: %s\n", payload);

  // In theory, it's at this point the payload may not be recognized by Anti Virus
  // When we're ready to execute it, we decrypt it.
  xor_encrypt_decrypt(payload, 'K');
  printf("Decrypted Payload: %s\n", payload);

  // Now we can execute out payload that
  hack();
  return 0;
}
