#include <stdio.h>
#include <string.h>

void FUN_00101218(char *param_1);


int main() {
    char local_118[264];
    strcpy(local_118, "fhz4yhx|~g=5");
    FUN_00101218(local_118);
    return 0;
}

void FUN_00101218(char *param_1) {
    int local_14;
    char *local_10;
  
    local_14 = 0x7b1;
    
    for (local_10 = param_1; *local_10 != '\0'; local_10 = local_10 + 1) {
        local_14 = (local_14 * 7) % 0x10000;
        *local_10 = *local_10 + ((char)(local_14 / 10) * '\n' - (char)local_14);
        printf("%c", *local_10);
    }
    //return param_1
}

