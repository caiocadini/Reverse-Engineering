# Reverse-Engineering
Resolução do Exercício [do site Crackmes.one](https://crackmes.one/crackme/5db0ef9f33c5d46f00e2c729)

## Analisando o problema inicial
![image](https://github.com/caiocadini/Reverse-Engineering/assets/99414301/57eed8e1-2796-4d77-93c9-32c3f7767acf)
Observa-se:
* Textos de "Don't patch it!" e "Insert your password:"
* input
## Analisando o arquivo login
O arquivo inicial apresentava a seguinte aparência ao se tentar lê-lo 
![image](https://github.com/caiocadini/Reverse-Engineering/assets/99414301/7e8ce219-9412-4118-9b2e-e1be2b34c60a)
Tornando-se necessário realizar seu tratamento

## Aplicando Ghidra
Usando o Ghidra, obtemos uma lista de funções após o processo de decompiling

![image](https://github.com/caiocadini/Reverse-Engineering/assets/99414301/c9c8acc0-06cb-40f8-ada1-3be6086f5c9f)

## Analisando a função entry
Começamos com a função entry por termos percebido a presença do seguinte código   
```
void processEntry entry(undefined8 param_1,undefined8 param_2)
{
  undefined auStack_8 [8];
  
__libc_start_main(FUN_001012a1,param_2,&stack0x00000008,FUN_00101460,FUN_001014c0,param_1,
                    auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```
analisando os parâmetros da função ``` __libc_start_main()```: ```int __libc_start_main(int (*main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end));```
* ```FUN_001012a1()``` é passada como a função main()

## Analisando FUN_001012a1()
```
{
  int iVar1;
  long in_FS_OFFSET;
  undefined local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  FUN_00101348("Gtu.}\'uj{fq!p{$",1); //Chama ela 2 vezes
  FUN_00101348(&DAT_00102014,0);
  __isoc99_scanf("%64[^\n]",local_58); //Espécie de scanf
  iVar1 = FUN_001013e3(local_58,"fhz4yhx|~g=5");
  if (iVar1 == 0) {
    FUN_00101348("Ftyynjy*",1);
  }
  else {
    FUN_00101348("Zwvup(",1);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
É reconhecível a função ```__isoc99_scanf```, algo semelhante como visto no input em "Insert your password"
Vendo a função anterior ```FUN_00101348```, observa-se que as strings passadas estão criptografadas
## Analisando FUN_00101348()
```
void FUN_00101348(char *param_1,char param_2)
{
  long in_FS_OFFSET;
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  strcpy(local_118,param_1); //Salva a primeira string 
  FUN_00101218(local_118); //O que é isso??
  if (param_2 == '\0') {
    fputs(local_118,stdout);
  }
  else {
    puts(local_118);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
Observa-se que ```local_118``` contém as strings passadas, que são aplicadas em uma nova função```FUN_00101218()```

## Analisando FUN_00101218()
```
char * FUN_00101218(char *param_1)

{
  int local_14;
  char *local_10;
  
  local_14 = 0x7b1;
  for (local_10 = param_1; *local_10 != '\0'; local_10 = local_10 + 1) {
    local_14 = (local_14 * 7) % 0x10000;
    *local_10 = *local_10 + ((char)(local_14 / 10) * '\n' - (char)local_14);
  }
  return param_1;
}
```
Analisando o funcionamento do loop:
* Começa no endereço inicial da string (primeiro caractere)
* Continua até chegar num caractere “\0”
* Incrementa indo para a próximo caractere
O que ocorre a cada loop?:
*```*local_10 = *local_10 + ((char)(local_14 / 10) * '\n' - (char)local_14);```
  * Atualiza o valor que já estava na mesma casa de ```local_10```, ou seja, estamos repondo a string por outra, que depois será retornada. Estamos descriptografando o texto
Aplicando o código na string “Gtu.}\'uj{fq!p{$” obtemos o output "Don't patch it!"

FUN_00101348(&DAT_00102014,0) -> "Insert your password"

FUN_00101348("Ftyynjy*",1) -> "Correct"

FUN_00101348("Zwvup(",1) -> "Wrong"

Estão ligados com o trecho de código da função ```FUN_001012a1()```
```
 iVar1 = FUN_001013e3(local_58,"fhz4yhx|~g=5"); //Necessário analisar essa func
  if (iVar1 == 0) {
    FUN_00101348("Ftyynjy*",1);
  }
  else {
    FUN_00101348("Zwvup(",1);
  }
```
O retorno de correto ou errado depende de ```FUN_001013e3()```
## Analisando FUN_001013e3()
```
undefined8 FUN_001013e3(char *param_1,undefined8 param_2) 

{
  char *pcVar1;
  char cVar2;
  undefined8 uVar3;
  char *local_20;
  int local_c;
  
  local_c = FUN_00101175(param_2);
  local_20 = param_1;
  while ((*local_20 != '\0' && (local_c != 0))) {
    pcVar1 = local_20 + 1;
    cVar2 = *local_20;
    local_20 = pcVar1;
    if (local_c != cVar2) break;
    local_c = FUN_00101175(0);
  }
  if ((local_c == 0) && (*local_20 == '\0')) {
    uVar3 = 0;
  }
  else {
    uVar3 = 1;
  }
  return uVar3;
}
```
Processo de análise da string inteira, retorna o valor que será analisado para dizer se a senha está correta ou não
* param_1 => nput analisado por __isoc99_scanf("%64[^\n]",local_58);
* param_2 => "fhz4yhx|~g=5"
Trata-se da validação da senha, "fhz4yhx|~g=5" muito provavelmente se trata da senha. Vamos agora analisar a ```FUN_00101175()```

## Analisando FUN_00101175()
```
nt FUN_00101175(char *param_1)

{
  int iVar1;
  
  if (param_1 != (char *)0x0) {
    DAT_00104010 = 0x7b1;
    DAT_00104028 = param_1;
  }
  if (*DAT_00104028 == '\0') {
    iVar1 = 0;
  }
  else {
    DAT_00104010 = (DAT_00104010 * 7) % 0x10000;
    iVar1 = (int)*DAT_00104028 + ((DAT_00104010 / 10) * 10 - DAT_00104010);
    DAT_00104028 = DAT_00104028 + 1;
  }
  return iVar1;
}
```
Lembra uma função que já vimos:
```
char * FUN_00101218(char *param_1)

{
  int local_14;
  char *local_10;
  
  local_14 = 0x7b1;
  for (local_10 = param_1; *local_10 != '\0'; local_10 = local_10 + 1) {
    local_14 = (local_14 * 7) % 0x10000;
    *local_10 = *local_10 + ((char)(local_14 / 10) * '\n' - (char)local_14);
  }
  return param_1;
}
```
Segue o processo de criptografia, porém dessa vez é alterada para retornar um valor inteiro que valide a senha.

É possível aplicar a string na função ```FUN_00101218()```?

```
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
```
O resultado é: 

![image](https://github.com/caiocadini/Reverse-Engineering/assets/99414301/846ff7fe-eb62-4278-a400-27903821b500)

Aplicando isto ao programa inicial:

![image](https://github.com/caiocadini/Reverse-Engineering/assets/99414301/1fbe97cf-99aa-4505-8b15-4d3ba99f6cd4)


