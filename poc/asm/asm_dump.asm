Reading symbols from ../poc_binary/poc_binary...
(No debugging symbols found in ../poc_binary/poc_binary)
Breakpoint 1 at 0x1158

Breakpoint 1, 0x0000555555555158 in main ()
Dump of assembler code for function main:
=> 0x0000555555555158 <+0>:	endbr64 
   0x000055555555515c <+4>:	push   %rbp
   0x000055555555515d <+5>:	mov    %rsp,%rbp
   0x0000555555555160 <+8>:	sub    $0x10,%rsp
   0x0000555555555164 <+12>:	movl   $0x0,-0x4(%rbp)
   0x000055555555516b <+19>:	mov    $0x0,%eax
   0x0000555555555170 <+24>:	callq  0x555555555149 <function>
   0x0000555555555175 <+29>:	cmpl   $0x0,-0x4(%rbp)
   0x0000555555555179 <+33>:	je     0x555555555189 <main+49>
   0x000055555555517b <+35>:	lea    0xe82(%rip),%rdi        # 0x555555556004
   0x0000555555555182 <+42>:	callq  0x555555555050 <puts@plt>
   0x0000555555555187 <+47>:	jmp    0x555555555195 <main+61>
   0x0000555555555189 <+49>:	lea    0xe79(%rip),%rdi        # 0x555555556009
   0x0000555555555190 <+56>:	callq  0x555555555050 <puts@plt>
   0x0000555555555195 <+61>:	mov    $0x0,%eax
   0x000055555555519a <+66>:	leaveq 
   0x000055555555519b <+67>:	retq   
End of assembler dump.
A debugging session is active.

	Inferior 1 [process 40028] will be killed.

Quit anyway? (y or n) [answered Y; input not from terminal]
