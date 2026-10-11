
revolution:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <.init>:
  401000:	f3 0f 1e fa          	endbr64
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 d1 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd1]        # 403fe0 <setvbuf@plt+0x2f20>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <write@plt-0x6a>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 ca 2f 00 00    	push   QWORD PTR [rip+0x2fca]        # 403ff0 <setvbuf@plt+0x2f30>
  401026:	ff 25 cc 2f 00 00    	jmp    QWORD PTR [rip+0x2fcc]        # 403ff8 <setvbuf@plt+0x2f38>
  40102c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401030:	f3 0f 1e fa          	endbr64
  401034:	68 00 00 00 00       	push   0x0
  401039:	e9 e2 ff ff ff       	jmp    401020 <write@plt-0x60>
  40103e:	66 90                	xchg   ax,ax
  401040:	f3 0f 1e fa          	endbr64
  401044:	68 01 00 00 00       	push   0x1
  401049:	e9 d2 ff ff ff       	jmp    401020 <write@plt-0x60>
  40104e:	66 90                	xchg   ax,ax
  401050:	f3 0f 1e fa          	endbr64
  401054:	68 02 00 00 00       	push   0x2
  401059:	e9 c2 ff ff ff       	jmp    401020 <write@plt-0x60>
  40105e:	66 90                	xchg   ax,ax
  401060:	f3 0f 1e fa          	endbr64
  401064:	68 03 00 00 00       	push   0x3
  401069:	e9 b2 ff ff ff       	jmp    401020 <write@plt-0x60>
  40106e:	66 90                	xchg   ax,ax
  401070:	f3 0f 1e fa          	endbr64
  401074:	68 04 00 00 00       	push   0x4
  401079:	e9 a2 ff ff ff       	jmp    401020 <write@plt-0x60>
  40107e:	66 90                	xchg   ax,ax

Disassembly of section .plt.sec:

0000000000401080 <write@plt>:
  401080:	f3 0f 1e fa          	endbr64
  401084:	ff 25 76 2f 00 00    	jmp    QWORD PTR [rip+0x2f76]        # 404000 <setvbuf@plt+0x2f40>
  40108a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000401090 <strlen@plt>:
  401090:	f3 0f 1e fa          	endbr64
  401094:	ff 25 6e 2f 00 00    	jmp    QWORD PTR [rip+0x2f6e]        # 404008 <setvbuf@plt+0x2f48>
  40109a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000004010a0 <strcspn@plt>:
  4010a0:	f3 0f 1e fa          	endbr64
  4010a4:	ff 25 66 2f 00 00    	jmp    QWORD PTR [rip+0x2f66]        # 404010 <setvbuf@plt+0x2f50>
  4010aa:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000004010b0 <read@plt>:
  4010b0:	f3 0f 1e fa          	endbr64
  4010b4:	ff 25 5e 2f 00 00    	jmp    QWORD PTR [rip+0x2f5e]        # 404018 <setvbuf@plt+0x2f58>
  4010ba:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000004010c0 <setvbuf@plt>:
  4010c0:	f3 0f 1e fa          	endbr64
  4010c4:	ff 25 56 2f 00 00    	jmp    QWORD PTR [rip+0x2f56]        # 404020 <setvbuf@plt+0x2f60>
  4010ca:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

00000000004010d0 <.text>:
  4010d0:	f3 0f 1e fa          	endbr64
  4010d4:	41 54                	push   r12
  4010d6:	ba 1f 00 00 00       	mov    edx,0x1f
  4010db:	48 8d 35 46 0f 00 00 	lea    rsi,[rip+0xf46]        # 402028 <setvbuf@plt+0xf68>
  4010e2:	bf 01 00 00 00       	mov    edi,0x1
  4010e7:	55                   	push   rbp
  4010e8:	4c 8d 25 2b 0f 00 00 	lea    r12,[rip+0xf2b]        # 40201a <setvbuf@plt+0xf5a>
  4010ef:	48 8d 2d 2c 0f 00 00 	lea    rbp,[rip+0xf2c]        # 402022 <setvbuf@plt+0xf62>
  4010f6:	53                   	push   rbx
  4010f7:	48 81 ec 00 02 00 00 	sub    rsp,0x200
  4010fe:	e8 7d ff ff ff       	call   401080 <write@plt>
  401103:	ba 20 00 00 00       	mov    edx,0x20
  401108:	bf 01 00 00 00       	mov    edi,0x1
  40110d:	48 89 e3             	mov    rbx,rsp
  401110:	48 8d 35 31 0f 00 00 	lea    rsi,[rip+0xf31]        # 402048 <setvbuf@plt+0xf88>
  401117:	e8 64 ff ff ff       	call   401080 <write@plt>
  40111c:	eb 31                	jmp    40114f <setvbuf@plt+0x8f>
  40111e:	66 90                	xchg   ax,ax
  401120:	48 89 ee             	mov    rsi,rbp
  401123:	48 89 df             	mov    rdi,rbx
  401126:	c6 04 04 00          	mov    BYTE PTR [rsp+rax*1],0x0
  40112a:	e8 71 ff ff ff       	call   4010a0 <strcspn@plt>
  40112f:	48 89 df             	mov    rdi,rbx
  401132:	c6 04 04 00          	mov    BYTE PTR [rsp+rax*1],0x0
  401136:	31 c0                	xor    eax,eax
  401138:	e8 f3 01 00 00       	call   401330 <setvbuf@plt+0x270>
  40113d:	ba 01 00 00 00       	mov    edx,0x1
  401142:	48 89 ee             	mov    rsi,rbp
  401145:	bf 01 00 00 00       	mov    edi,0x1
  40114a:	e8 31 ff ff ff       	call   401080 <write@plt>
  40114f:	ba 07 00 00 00       	mov    edx,0x7
  401154:	4c 89 e6             	mov    rsi,r12
  401157:	bf 01 00 00 00       	mov    edi,0x1
  40115c:	e8 1f ff ff ff       	call   401080 <write@plt>
  401161:	31 ff                	xor    edi,edi
  401163:	ba ff 01 00 00       	mov    edx,0x1ff
  401168:	48 89 de             	mov    rsi,rbx
  40116b:	e8 40 ff ff ff       	call   4010b0 <read@plt>
  401170:	48 85 c0             	test   rax,rax
  401173:	7f ab                	jg     401120 <setvbuf@plt+0x60>
  401175:	48 81 c4 00 02 00 00 	add    rsp,0x200
  40117c:	31 c0                	xor    eax,eax
  40117e:	5b                   	pop    rbx
  40117f:	5d                   	pop    rbp
  401180:	41 5c                	pop    r12
  401182:	c3                   	ret
  401183:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40118a:	00 00 00 
  40118d:	0f 1f 00             	nop    DWORD PTR [rax]
  401190:	f3 0f 1e fa          	endbr64
  401194:	48 83 ec 08          	sub    rsp,0x8
  401198:	48 8b 3d a1 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2ea1]        # 404040 <stdout@GLIBC_2.2.5>
  40119f:	31 c9                	xor    ecx,ecx
  4011a1:	31 f6                	xor    esi,esi
  4011a3:	ba 02 00 00 00       	mov    edx,0x2
  4011a8:	e8 13 ff ff ff       	call   4010c0 <setvbuf@plt>
  4011ad:	48 8b 3d ac 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2eac]        # 404060 <stderr@GLIBC_2.2.5>
  4011b4:	31 c9                	xor    ecx,ecx
  4011b6:	31 f6                	xor    esi,esi
  4011b8:	ba 02 00 00 00       	mov    edx,0x2
  4011bd:	48 83 c4 08          	add    rsp,0x8
  4011c1:	e9 fa fe ff ff       	jmp    4010c0 <setvbuf@plt>
  4011c6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  4011cd:	00 00 00 
  4011d0:	f3 0f 1e fa          	endbr64
  4011d4:	31 ed                	xor    ebp,ebp
  4011d6:	49 89 d1             	mov    r9,rdx
  4011d9:	5e                   	pop    rsi
  4011da:	48 89 e2             	mov    rdx,rsp
  4011dd:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  4011e1:	50                   	push   rax
  4011e2:	54                   	push   rsp
  4011e3:	45 31 c0             	xor    r8d,r8d
  4011e6:	31 c9                	xor    ecx,ecx
  4011e8:	48 c7 c7 d0 10 40 00 	mov    rdi,0x4010d0
  4011ef:	ff 15 e3 2d 00 00    	call   QWORD PTR [rip+0x2de3]        # 403fd8 <setvbuf@plt+0x2f18>
  4011f5:	f4                   	hlt
  4011f6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  4011fd:	00 00 00 
  401200:	f3 0f 1e fa          	endbr64
  401204:	c3                   	ret
  401205:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40120c:	00 00 00 
  40120f:	90                   	nop
  401210:	b8 38 40 40 00       	mov    eax,0x404038
  401215:	48 3d 38 40 40 00    	cmp    rax,0x404038
  40121b:	74 13                	je     401230 <setvbuf@plt+0x170>
  40121d:	b8 00 00 00 00       	mov    eax,0x0
  401222:	48 85 c0             	test   rax,rax
  401225:	74 09                	je     401230 <setvbuf@plt+0x170>
  401227:	bf 38 40 40 00       	mov    edi,0x404038
  40122c:	ff e0                	jmp    rax
  40122e:	66 90                	xchg   ax,ax
  401230:	c3                   	ret
  401231:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  401238:	00 00 00 00 
  40123c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401240:	be 38 40 40 00       	mov    esi,0x404038
  401245:	48 81 ee 38 40 40 00 	sub    rsi,0x404038
  40124c:	48 89 f0             	mov    rax,rsi
  40124f:	48 c1 ee 3f          	shr    rsi,0x3f
  401253:	48 c1 f8 03          	sar    rax,0x3
  401257:	48 01 c6             	add    rsi,rax
  40125a:	48 d1 fe             	sar    rsi,1
  40125d:	74 11                	je     401270 <setvbuf@plt+0x1b0>
  40125f:	b8 00 00 00 00       	mov    eax,0x0
  401264:	48 85 c0             	test   rax,rax
  401267:	74 07                	je     401270 <setvbuf@plt+0x1b0>
  401269:	bf 38 40 40 00       	mov    edi,0x404038
  40126e:	ff e0                	jmp    rax
  401270:	c3                   	ret
  401271:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  401278:	00 00 00 00 
  40127c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401280:	f3 0f 1e fa          	endbr64
  401284:	80 3d dd 2d 00 00 00 	cmp    BYTE PTR [rip+0x2ddd],0x0        # 404068 <stderr@GLIBC_2.2.5+0x8>
  40128b:	75 13                	jne    4012a0 <setvbuf@plt+0x1e0>
  40128d:	55                   	push   rbp
  40128e:	48 89 e5             	mov    rbp,rsp
  401291:	e8 7a ff ff ff       	call   401210 <setvbuf@plt+0x150>
  401296:	c6 05 cb 2d 00 00 01 	mov    BYTE PTR [rip+0x2dcb],0x1        # 404068 <stderr@GLIBC_2.2.5+0x8>
  40129d:	5d                   	pop    rbp
  40129e:	c3                   	ret
  40129f:	90                   	nop
  4012a0:	c3                   	ret
  4012a1:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  4012a8:	00 00 00 00 
  4012ac:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  4012b0:	f3 0f 1e fa          	endbr64
  4012b4:	eb 8a                	jmp    401240 <setvbuf@plt+0x180>
  4012b6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  4012bd:	00 00 00 
  4012c0:	f3 0f 6f 07          	movdqu xmm0,XMMWORD PTR [rdi]
  4012c4:	0f 11 44 24 e0       	movups XMMWORD PTR [rsp-0x20],xmm0
  4012c9:	48 8b 7f 10          	mov    rdi,QWORD PTR [rdi+0x10]
  4012cd:	48 89 7c 24 f0       	mov    QWORD PTR [rsp-0x10],rdi
  4012d2:	85 f6                	test   esi,esi
  4012d4:	7e 4a                	jle    401320 <setvbuf@plt+0x260>
  4012d6:	31 c9                	xor    ecx,ecx
  4012d8:	eb 1c                	jmp    4012f6 <setvbuf@plt+0x236>
  4012da:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  4012e0:	89 c2                	mov    edx,eax
  4012e2:	83 c1 01             	add    ecx,0x1
  4012e5:	83 c0 08             	add    eax,0x8
  4012e8:	48 01 fa             	add    rdx,rdi
  4012eb:	89 44 24 e0          	mov    DWORD PTR [rsp-0x20],eax
  4012ef:	48 8b 02             	mov    rax,QWORD PTR [rdx]
  4012f2:	39 ce                	cmp    esi,ecx
  4012f4:	74 21                	je     401317 <setvbuf@plt+0x257>
  4012f6:	8b 44 24 e0          	mov    eax,DWORD PTR [rsp-0x20]
  4012fa:	83 f8 2f             	cmp    eax,0x2f
  4012fd:	76 e1                	jbe    4012e0 <setvbuf@plt+0x220>
  4012ff:	48 8b 54 24 e8       	mov    rdx,QWORD PTR [rsp-0x18]
  401304:	83 c1 01             	add    ecx,0x1
  401307:	48 8d 42 08          	lea    rax,[rdx+0x8]
  40130b:	48 89 44 24 e8       	mov    QWORD PTR [rsp-0x18],rax
  401310:	48 8b 02             	mov    rax,QWORD PTR [rdx]
  401313:	39 ce                	cmp    esi,ecx
  401315:	75 df                	jne    4012f6 <setvbuf@plt+0x236>
  401317:	c3                   	ret
  401318:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  40131f:	00 
  401320:	31 c0                	xor    eax,eax
  401322:	c3                   	ret
  401323:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  40132a:	00 00 00 00 
  40132e:	66 90                	xchg   ax,ax
  401330:	41 57                	push   r15
  401332:	49 89 ff             	mov    r15,rdi
  401335:	41 56                	push   r14
  401337:	41 55                	push   r13
  401339:	41 54                	push   r12
  40133b:	55                   	push   rbp
  40133c:	53                   	push   rbx
  40133d:	48 81 ec e8 00 00 00 	sub    rsp,0xe8
  401344:	48 89 74 24 38       	mov    QWORD PTR [rsp+0x38],rsi
  401349:	48 89 54 24 40       	mov    QWORD PTR [rsp+0x40],rdx
  40134e:	48 89 4c 24 48       	mov    QWORD PTR [rsp+0x48],rcx
  401353:	4c 89 44 24 50       	mov    QWORD PTR [rsp+0x50],r8
  401358:	4c 89 4c 24 58       	mov    QWORD PTR [rsp+0x58],r9
  40135d:	84 c0                	test   al,al
  40135f:	74 3a                	je     40139b <setvbuf@plt+0x2db>
  401361:	0f 29 44 24 60       	movaps XMMWORD PTR [rsp+0x60],xmm0
  401366:	0f 29 4c 24 70       	movaps XMMWORD PTR [rsp+0x70],xmm1
  40136b:	0f 29 94 24 80 00 00 	movaps XMMWORD PTR [rsp+0x80],xmm2
  401372:	00 
  401373:	0f 29 9c 24 90 00 00 	movaps XMMWORD PTR [rsp+0x90],xmm3
  40137a:	00 
  40137b:	0f 29 a4 24 a0 00 00 	movaps XMMWORD PTR [rsp+0xa0],xmm4
  401382:	00 
  401383:	0f 29 ac 24 b0 00 00 	movaps XMMWORD PTR [rsp+0xb0],xmm5
  40138a:	00 
  40138b:	0f 29 b4 24 c0 00 00 	movaps XMMWORD PTR [rsp+0xc0],xmm6
  401392:	00 
  401393:	0f 29 bc 24 d0 00 00 	movaps XMMWORD PTR [rsp+0xd0],xmm7
  40139a:	00 
  40139b:	31 db                	xor    ebx,ebx
  40139d:	4c 8d 25 62 0c 00 00 	lea    r12,[rip+0xc62]        # 402006 <setvbuf@plt+0xf46>
  4013a4:	4c 8d 35 5e 0c 00 00 	lea    r14,[rip+0xc5e]        # 402009 <setvbuf@plt+0xf49>
  4013ab:	c7 44 24 18 08 00 00 	mov    DWORD PTR [rsp+0x18],0x8
  4013b2:	00 
  4013b3:	48 8d 84 24 20 01 00 	lea    rax,[rsp+0x120]
  4013ba:	00 
  4013bb:	c7 44 24 1c 30 00 00 	mov    DWORD PTR [rsp+0x1c],0x30
  4013c2:	00 
  4013c3:	48 8d 2d 3a 0c 00 00 	lea    rbp,[rip+0xc3a]        # 402004 <setvbuf@plt+0xf44>
  4013ca:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
  4013cf:	48 8d 44 24 30       	lea    rax,[rsp+0x30]
  4013d4:	48 89 44 24 28       	mov    QWORD PTR [rsp+0x28],rax
  4013d9:	41 0f b6 07          	movzx  eax,BYTE PTR [r15]
  4013dd:	84 c0                	test   al,al
  4013df:	0f 84 ac 00 00 00    	je     401491 <setvbuf@plt+0x3d1>
  4013e5:	0f 1f 00             	nop    DWORD PTR [rax]
  4013e8:	3c 25                	cmp    al,0x25
  4013ea:	0f 85 b8 00 00 00    	jne    4014a8 <setvbuf@plt+0x3e8>
  4013f0:	41 0f b6 47 01       	movzx  eax,BYTE PTR [r15+0x1]
  4013f5:	4d 8d 6f 01          	lea    r13,[r15+0x1]
  4013f9:	3c 25                	cmp    al,0x25
  4013fb:	0f 84 07 01 00 00    	je     401508 <setvbuf@plt+0x448>
  401401:	84 c0                	test   al,al
  401403:	0f 84 88 00 00 00    	je     401491 <setvbuf@plt+0x3d1>
  401409:	8d 50 d0             	lea    edx,[rax-0x30]
  40140c:	80 fa 09             	cmp    dl,0x9
  40140f:	0f 87 ab 00 00 00    	ja     4014c0 <setvbuf@plt+0x400>
  401415:	31 f6                	xor    esi,esi
  401417:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  40141e:	00 00 
  401420:	83 e8 30             	sub    eax,0x30
  401423:	8d 14 b6             	lea    edx,[rsi+rsi*4]
  401426:	4c 89 e9             	mov    rcx,r13
  401429:	49 83 c5 01          	add    r13,0x1
  40142d:	0f be c0             	movsx  eax,al
  401430:	8d 34 50             	lea    esi,[rax+rdx*2]
  401433:	41 0f b6 45 00       	movzx  eax,BYTE PTR [r13+0x0]
  401438:	8d 50 d0             	lea    edx,[rax-0x30]
  40143b:	80 fa 09             	cmp    dl,0x9
  40143e:	76 e0                	jbe    401420 <setvbuf@plt+0x360>
  401440:	3c 24                	cmp    al,0x24
  401442:	75 3c                	jne    401480 <setvbuf@plt+0x3c0>
  401444:	0f b6 41 02          	movzx  eax,BYTE PTR [rcx+0x2]
  401448:	4c 8d 69 02          	lea    r13,[rcx+0x2]
  40144c:	3c 77                	cmp    al,0x77
  40144e:	74 7d                	je     4014cd <setvbuf@plt+0x40d>
  401450:	0f 8f ca 00 00 00    	jg     401520 <setvbuf@plt+0x460>
  401456:	3c 70                	cmp    al,0x70
  401458:	0f 84 e2 00 00 00    	je     401540 <setvbuf@plt+0x480>
  40145e:	3c 73                	cmp    al,0x73
  401460:	0f 85 be 00 00 00    	jne    401524 <setvbuf@plt+0x464>
  401466:	48 8d 7c 24 18       	lea    rdi,[rsp+0x18]
  40146b:	e8 50 fe ff ff       	call   4012c0 <setvbuf@plt+0x200>
  401470:	49 89 c7             	mov    r15,rax
  401473:	48 85 c0             	test   rax,rax
  401476:	0f 85 21 01 00 00    	jne    40159d <setvbuf@plt+0x4dd>
  40147c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401480:	41 0f b6 45 01       	movzx  eax,BYTE PTR [r13+0x1]
  401485:	4d 8d 7d 01          	lea    r15,[r13+0x1]
  401489:	84 c0                	test   al,al
  40148b:	0f 85 57 ff ff ff    	jne    4013e8 <setvbuf@plt+0x328>
  401491:	48 81 c4 e8 00 00 00 	add    rsp,0xe8
  401498:	5b                   	pop    rbx
  401499:	5d                   	pop    rbp
  40149a:	41 5c                	pop    r12
  40149c:	41 5d                	pop    r13
  40149e:	41 5e                	pop    r14
  4014a0:	41 5f                	pop    r15
  4014a2:	c3                   	ret
  4014a3:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  4014a8:	ba 01 00 00 00       	mov    edx,0x1
  4014ad:	4c 89 fe             	mov    rsi,r15
  4014b0:	bf 01 00 00 00       	mov    edi,0x1
  4014b5:	4d 89 fd             	mov    r13,r15
  4014b8:	e8 c3 fb ff ff       	call   401080 <write@plt>
  4014bd:	eb c1                	jmp    401480 <setvbuf@plt+0x3c0>
  4014bf:	90                   	nop
  4014c0:	83 c3 01             	add    ebx,0x1
  4014c3:	89 de                	mov    esi,ebx
  4014c5:	3c 77                	cmp    al,0x77
  4014c7:	0f 85 83 ff ff ff    	jne    401450 <setvbuf@plt+0x390>
  4014cd:	4c 8d 4c 24 18       	lea    r9,[rsp+0x18]
  4014d2:	4c 89 cf             	mov    rdi,r9
  4014d5:	e8 e6 fd ff ff       	call   4012c0 <setvbuf@plt+0x200>
  4014da:	83 c6 01             	add    esi,0x1
  4014dd:	4c 89 cf             	mov    rdi,r9
  4014e0:	49 89 c0             	mov    r8,rax
  4014e3:	e8 d8 fd ff ff       	call   4012c0 <setvbuf@plt+0x200>
  4014e8:	ba 02 00 00 00       	mov    edx,0x2
  4014ed:	4c 89 e6             	mov    rsi,r12
  4014f0:	bf 01 00 00 00       	mov    edi,0x1
  4014f5:	49 89 00             	mov    QWORD PTR [r8],rax
  4014f8:	e8 83 fb ff ff       	call   401080 <write@plt>
  4014fd:	e9 7e ff ff ff       	jmp    401480 <setvbuf@plt+0x3c0>
  401502:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  401508:	ba 01 00 00 00       	mov    edx,0x1
  40150d:	48 89 ee             	mov    rsi,rbp
  401510:	bf 01 00 00 00       	mov    edi,0x1
  401515:	e8 66 fb ff ff       	call   401080 <write@plt>
  40151a:	e9 61 ff ff ff       	jmp    401480 <setvbuf@plt+0x3c0>
  40151f:	90                   	nop
  401520:	3c 78                	cmp    al,0x78
  401522:	74 1c                	je     401540 <setvbuf@plt+0x480>
  401524:	ba 01 00 00 00       	mov    edx,0x1
  401529:	4c 89 ee             	mov    rsi,r13
  40152c:	bf 01 00 00 00       	mov    edi,0x1
  401531:	e8 4a fb ff ff       	call   401080 <write@plt>
  401536:	e9 45 ff ff ff       	jmp    401480 <setvbuf@plt+0x3c0>
  40153b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  401540:	48 8d 7c 24 18       	lea    rdi,[rsp+0x18]
  401545:	e8 76 fd ff ff       	call   4012c0 <setvbuf@plt+0x200>
  40154a:	48 8d 54 24 02       	lea    rdx,[rsp+0x2]
  40154f:	b9 3c 00 00 00       	mov    ecx,0x3c
  401554:	0f b7 3d 0f 0b 00 00 	movzx  edi,WORD PTR [rip+0xb0f]        # 40206a <setvbuf@plt+0xfaa>
  40155b:	66 89 3c 24          	mov    WORD PTR [rsp],di
  40155f:	48 8d 7c 24 12       	lea    rdi,[rsp+0x12]
  401564:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401568:	48 89 c6             	mov    rsi,rax
  40156b:	48 83 c2 01          	add    rdx,0x1
  40156f:	48 d3 ee             	shr    rsi,cl
  401572:	83 e9 04             	sub    ecx,0x4
  401575:	83 e6 0f             	and    esi,0xf
  401578:	41 0f b6 34 36       	movzx  esi,BYTE PTR [r14+rsi*1]
  40157d:	40 88 72 ff          	mov    BYTE PTR [rdx-0x1],sil
  401581:	48 39 d7             	cmp    rdi,rdx
  401584:	75 e2                	jne    401568 <setvbuf@plt+0x4a8>
  401586:	48 89 e6             	mov    rsi,rsp
  401589:	ba 12 00 00 00       	mov    edx,0x12
  40158e:	bf 01 00 00 00       	mov    edi,0x1
  401593:	e8 e8 fa ff ff       	call   401080 <write@plt>
  401598:	e9 e3 fe ff ff       	jmp    401480 <setvbuf@plt+0x3c0>
  40159d:	48 89 c7             	mov    rdi,rax
  4015a0:	e8 eb fa ff ff       	call   401090 <strlen@plt>
  4015a5:	4c 89 fe             	mov    rsi,r15
  4015a8:	bf 01 00 00 00       	mov    edi,0x1
  4015ad:	48 89 c2             	mov    rdx,rax
  4015b0:	e8 cb fa ff ff       	call   401080 <write@plt>
  4015b5:	e9 c6 fe ff ff       	jmp    401480 <setvbuf@plt+0x3c0>

Disassembly of section .fini:

00000000004015bc <.fini>:
  4015bc:	f3 0f 1e fa          	endbr64
  4015c0:	48 83 ec 08          	sub    rsp,0x8
  4015c4:	48 83 c4 08          	add    rsp,0x8
  4015c8:	c3                   	ret
