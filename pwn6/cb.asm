
code_breaker:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <.init>:
    1000:	f3 0f 1e fa          	endbr64
    1004:	48 83 ec 08          	sub    rsp,0x8
    1008:	48 8b 05 c1 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fc1]        # 3fd0 <fopen@plt+0x2e20>
    100f:	48 85 c0             	test   rax,rax
    1012:	74 02                	je     1016 <__cxa_finalize@plt-0xda>
    1014:	ff d0                	call   rax
    1016:	48 83 c4 08          	add    rsp,0x8
    101a:	c3                   	ret

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 ca 2f 00 00    	push   QWORD PTR [rip+0x2fca]        # 3ff0 <fopen@plt+0x2e40>
    1026:	ff 25 cc 2f 00 00    	jmp    QWORD PTR [rip+0x2fcc]        # 3ff8 <fopen@plt+0x2e48>
    102c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    1030:	f3 0f 1e fa          	endbr64
    1034:	68 00 00 00 00       	push   0x0
    1039:	e9 e2 ff ff ff       	jmp    1020 <__cxa_finalize@plt-0xd0>
    103e:	66 90                	xchg   ax,ax
    1040:	f3 0f 1e fa          	endbr64
    1044:	68 01 00 00 00       	push   0x1
    1049:	e9 d2 ff ff ff       	jmp    1020 <__cxa_finalize@plt-0xd0>
    104e:	66 90                	xchg   ax,ax
    1050:	f3 0f 1e fa          	endbr64
    1054:	68 02 00 00 00       	push   0x2
    1059:	e9 c2 ff ff ff       	jmp    1020 <__cxa_finalize@plt-0xd0>
    105e:	66 90                	xchg   ax,ax
    1060:	f3 0f 1e fa          	endbr64
    1064:	68 03 00 00 00       	push   0x3
    1069:	e9 b2 ff ff ff       	jmp    1020 <__cxa_finalize@plt-0xd0>
    106e:	66 90                	xchg   ax,ax
    1070:	f3 0f 1e fa          	endbr64
    1074:	68 04 00 00 00       	push   0x4
    1079:	e9 a2 ff ff ff       	jmp    1020 <__cxa_finalize@plt-0xd0>
    107e:	66 90                	xchg   ax,ax
    1080:	f3 0f 1e fa          	endbr64
    1084:	68 05 00 00 00       	push   0x5
    1089:	e9 92 ff ff ff       	jmp    1020 <__cxa_finalize@plt-0xd0>
    108e:	66 90                	xchg   ax,ax
    1090:	f3 0f 1e fa          	endbr64
    1094:	68 06 00 00 00       	push   0x6
    1099:	e9 82 ff ff ff       	jmp    1020 <__cxa_finalize@plt-0xd0>
    109e:	66 90                	xchg   ax,ax
    10a0:	f3 0f 1e fa          	endbr64
    10a4:	68 07 00 00 00       	push   0x7
    10a9:	e9 72 ff ff ff       	jmp    1020 <__cxa_finalize@plt-0xd0>
    10ae:	66 90                	xchg   ax,ax
    10b0:	f3 0f 1e fa          	endbr64
    10b4:	68 08 00 00 00       	push   0x8
    10b9:	e9 62 ff ff ff       	jmp    1020 <__cxa_finalize@plt-0xd0>
    10be:	66 90                	xchg   ax,ax
    10c0:	f3 0f 1e fa          	endbr64
    10c4:	68 09 00 00 00       	push   0x9
    10c9:	e9 52 ff ff ff       	jmp    1020 <__cxa_finalize@plt-0xd0>
    10ce:	66 90                	xchg   ax,ax
    10d0:	f3 0f 1e fa          	endbr64
    10d4:	68 0a 00 00 00       	push   0xa
    10d9:	e9 42 ff ff ff       	jmp    1020 <__cxa_finalize@plt-0xd0>
    10de:	66 90                	xchg   ax,ax
    10e0:	f3 0f 1e fa          	endbr64
    10e4:	68 0b 00 00 00       	push   0xb
    10e9:	e9 32 ff ff ff       	jmp    1020 <__cxa_finalize@plt-0xd0>
    10ee:	66 90                	xchg   ax,ax

Disassembly of section .plt.got:

00000000000010f0 <__cxa_finalize@plt>:
    10f0:	f3 0f 1e fa          	endbr64
    10f4:	ff 25 e6 2e 00 00    	jmp    QWORD PTR [rip+0x2ee6]        # 3fe0 <fopen@plt+0x2e30>
    10fa:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

Disassembly of section .plt.sec:

0000000000001100 <free@plt>:
    1100:	f3 0f 1e fa          	endbr64
    1104:	ff 25 f6 2e 00 00    	jmp    QWORD PTR [rip+0x2ef6]        # 4000 <fopen@plt+0x2e50>
    110a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000001110 <fread@plt>:
    1110:	f3 0f 1e fa          	endbr64
    1114:	ff 25 ee 2e 00 00    	jmp    QWORD PTR [rip+0x2eee]        # 4008 <fopen@plt+0x2e58>
    111a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000001120 <write@plt>:
    1120:	f3 0f 1e fa          	endbr64
    1124:	ff 25 e6 2e 00 00    	jmp    QWORD PTR [rip+0x2ee6]        # 4010 <fopen@plt+0x2e60>
    112a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000001130 <fclose@plt>:
    1130:	f3 0f 1e fa          	endbr64
    1134:	ff 25 de 2e 00 00    	jmp    QWORD PTR [rip+0x2ede]        # 4018 <fopen@plt+0x2e68>
    113a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000001140 <__stack_chk_fail@plt>:
    1140:	f3 0f 1e fa          	endbr64
    1144:	ff 25 d6 2e 00 00    	jmp    QWORD PTR [rip+0x2ed6]        # 4020 <fopen@plt+0x2e70>
    114a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000001150 <system@plt>:
    1150:	f3 0f 1e fa          	endbr64
    1154:	ff 25 ce 2e 00 00    	jmp    QWORD PTR [rip+0x2ece]        # 4028 <fopen@plt+0x2e78>
    115a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000001160 <read@plt>:
    1160:	f3 0f 1e fa          	endbr64
    1164:	ff 25 c6 2e 00 00    	jmp    QWORD PTR [rip+0x2ec6]        # 4030 <fopen@plt+0x2e80>
    116a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000001170 <__memcpy_chk@plt>:
    1170:	f3 0f 1e fa          	endbr64
    1174:	ff 25 be 2e 00 00    	jmp    QWORD PTR [rip+0x2ebe]        # 4038 <fopen@plt+0x2e88>
    117a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000001180 <memcpy@plt>:
    1180:	f3 0f 1e fa          	endbr64
    1184:	ff 25 b6 2e 00 00    	jmp    QWORD PTR [rip+0x2eb6]        # 4040 <fopen@plt+0x2e90>
    118a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000001190 <malloc@plt>:
    1190:	f3 0f 1e fa          	endbr64
    1194:	ff 25 ae 2e 00 00    	jmp    QWORD PTR [rip+0x2eae]        # 4048 <fopen@plt+0x2e98>
    119a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000000011a0 <setvbuf@plt>:
    11a0:	f3 0f 1e fa          	endbr64
    11a4:	ff 25 a6 2e 00 00    	jmp    QWORD PTR [rip+0x2ea6]        # 4050 <fopen@plt+0x2ea0>
    11aa:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000000011b0 <fopen@plt>:
    11b0:	f3 0f 1e fa          	endbr64
    11b4:	ff 25 9e 2e 00 00    	jmp    QWORD PTR [rip+0x2e9e]        # 4058 <fopen@plt+0x2ea8>
    11ba:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

00000000000011c0 <.text>:
    11c0:	f3 0f 1e fa          	endbr64
    11c4:	48 83 ec 08          	sub    rsp,0x8
    11c8:	48 8d 3d 44 0e 00 00 	lea    rdi,[rip+0xe44]        # 2013 <fopen@plt+0xe63>
    11cf:	e8 7c ff ff ff       	call   1150 <system@plt>
    11d4:	66 0f 6f 05 64 0f 00 	movdqa xmm0,XMMWORD PTR [rip+0xf64]        # 2140 <fopen@plt+0xf90>
    11db:	00 
    11dc:	48 8d 05 ad 01 00 00 	lea    rax,[rip+0x1ad]        # 1390 <fopen@plt+0x1e0>
    11e3:	31 d2                	xor    edx,edx
    11e5:	48 89 05 d4 2e 00 00 	mov    QWORD PTR [rip+0x2ed4],rax        # 40c0 <stderr@GLIBC_2.2.5+0x20>
    11ec:	48 b8 32 2e 31 2e 34 	movabs rax,0x342e312e32
    11f3:	00 00 00 
    11f6:	0f 11 05 cb 2e 00 00 	movups XMMWORD PTR [rip+0x2ecb],xmm0        # 40c8 <stderr@GLIBC_2.2.5+0x28>
    11fd:	66 0f ef c0          	pxor   xmm0,xmm0
    1201:	48 89 15 08 2f 00 00 	mov    QWORD PTR [rip+0x2f08],rdx        # 4110 <stderr@GLIBC_2.2.5+0x70>
    1208:	0f 11 05 d9 2e 00 00 	movups XMMWORD PTR [rip+0x2ed9],xmm0        # 40e8 <stderr@GLIBC_2.2.5+0x48>
    120f:	48 89 05 f2 2e 00 00 	mov    QWORD PTR [rip+0x2ef2],rax        # 4108 <stderr@GLIBC_2.2.5+0x68>
    1216:	c7 05 08 2f 00 00 30 	mov    DWORD PTR [rip+0x2f08],0x30        # 4128 <stderr@GLIBC_2.2.5+0x88>
    121d:	00 00 00 
    1220:	0f 11 05 b1 2e 00 00 	movups XMMWORD PTR [rip+0x2eb1],xmm0        # 40d8 <stderr@GLIBC_2.2.5+0x38>
    1227:	0f 11 05 c9 2e 00 00 	movups XMMWORD PTR [rip+0x2ec9],xmm0        # 40f7 <stderr@GLIBC_2.2.5+0x57>
    122e:	0f 11 05 e2 2e 00 00 	movups XMMWORD PTR [rip+0x2ee2],xmm0        # 4117 <stderr@GLIBC_2.2.5+0x77>
    1235:	e8 36 04 00 00       	call   1670 <fopen@plt+0x4c0>
    123a:	89 c2                	mov    edx,eax
    123c:	b8 01 00 00 00       	mov    eax,0x1
    1241:	85 d2                	test   edx,edx
    1243:	78 07                	js     124c <fopen@plt+0x9c>
    1245:	e8 b6 06 00 00       	call   1900 <fopen@plt+0x750>
    124a:	31 c0                	xor    eax,eax
    124c:	48 83 c4 08          	add    rsp,0x8
    1250:	c3                   	ret
    1251:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    1258:	00 00 00 
    125b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1260:	f3 0f 1e fa          	endbr64
    1264:	48 83 ec 08          	sub    rsp,0x8
    1268:	48 8b 3d 11 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2e11]        # 4080 <stdout@GLIBC_2.2.5>
    126f:	31 c9                	xor    ecx,ecx
    1271:	31 f6                	xor    esi,esi
    1273:	ba 02 00 00 00       	mov    edx,0x2
    1278:	e8 23 ff ff ff       	call   11a0 <setvbuf@plt>
    127d:	48 8b 3d 1c 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2e1c]        # 40a0 <stderr@GLIBC_2.2.5>
    1284:	31 c9                	xor    ecx,ecx
    1286:	31 f6                	xor    esi,esi
    1288:	ba 02 00 00 00       	mov    edx,0x2
    128d:	48 83 c4 08          	add    rsp,0x8
    1291:	e9 0a ff ff ff       	jmp    11a0 <setvbuf@plt>
    1296:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    129d:	00 00 00 
    12a0:	f3 0f 1e fa          	endbr64
    12a4:	31 ed                	xor    ebp,ebp
    12a6:	49 89 d1             	mov    r9,rdx
    12a9:	5e                   	pop    rsi
    12aa:	48 89 e2             	mov    rdx,rsp
    12ad:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    12b1:	50                   	push   rax
    12b2:	54                   	push   rsp
    12b3:	45 31 c0             	xor    r8d,r8d
    12b6:	31 c9                	xor    ecx,ecx
    12b8:	48 8d 3d 01 ff ff ff 	lea    rdi,[rip+0xffffffffffffff01]        # 11c0 <fopen@plt+0x10>
    12bf:	ff 15 fb 2c 00 00    	call   QWORD PTR [rip+0x2cfb]        # 3fc0 <fopen@plt+0x2e10>
    12c5:	f4                   	hlt
    12c6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    12cd:	00 00 00 
    12d0:	48 8d 3d 99 2d 00 00 	lea    rdi,[rip+0x2d99]        # 4070 <fopen@plt+0x2ec0>
    12d7:	48 8d 05 92 2d 00 00 	lea    rax,[rip+0x2d92]        # 4070 <fopen@plt+0x2ec0>
    12de:	48 39 f8             	cmp    rax,rdi
    12e1:	74 15                	je     12f8 <fopen@plt+0x148>
    12e3:	48 8b 05 de 2c 00 00 	mov    rax,QWORD PTR [rip+0x2cde]        # 3fc8 <fopen@plt+0x2e18>
    12ea:	48 85 c0             	test   rax,rax
    12ed:	74 09                	je     12f8 <fopen@plt+0x148>
    12ef:	ff e0                	jmp    rax
    12f1:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    12f8:	c3                   	ret
    12f9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1300:	48 8d 3d 69 2d 00 00 	lea    rdi,[rip+0x2d69]        # 4070 <fopen@plt+0x2ec0>
    1307:	48 8d 35 62 2d 00 00 	lea    rsi,[rip+0x2d62]        # 4070 <fopen@plt+0x2ec0>
    130e:	48 29 fe             	sub    rsi,rdi
    1311:	48 89 f0             	mov    rax,rsi
    1314:	48 c1 ee 3f          	shr    rsi,0x3f
    1318:	48 c1 f8 03          	sar    rax,0x3
    131c:	48 01 c6             	add    rsi,rax
    131f:	48 d1 fe             	sar    rsi,1
    1322:	74 14                	je     1338 <fopen@plt+0x188>
    1324:	48 8b 05 ad 2c 00 00 	mov    rax,QWORD PTR [rip+0x2cad]        # 3fd8 <fopen@plt+0x2e28>
    132b:	48 85 c0             	test   rax,rax
    132e:	74 08                	je     1338 <fopen@plt+0x188>
    1330:	ff e0                	jmp    rax
    1332:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1338:	c3                   	ret
    1339:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1340:	f3 0f 1e fa          	endbr64
    1344:	80 3d 5d 2d 00 00 00 	cmp    BYTE PTR [rip+0x2d5d],0x0        # 40a8 <stderr@GLIBC_2.2.5+0x8>
    134b:	75 2b                	jne    1378 <fopen@plt+0x1c8>
    134d:	55                   	push   rbp
    134e:	48 83 3d 8a 2c 00 00 	cmp    QWORD PTR [rip+0x2c8a],0x0        # 3fe0 <fopen@plt+0x2e30>
    1355:	00 
    1356:	48 89 e5             	mov    rbp,rsp
    1359:	74 0c                	je     1367 <fopen@plt+0x1b7>
    135b:	48 8b 3d 06 2d 00 00 	mov    rdi,QWORD PTR [rip+0x2d06]        # 4068 <fopen@plt+0x2eb8>
    1362:	e8 89 fd ff ff       	call   10f0 <__cxa_finalize@plt>
    1367:	e8 64 ff ff ff       	call   12d0 <fopen@plt+0x120>
    136c:	c6 05 35 2d 00 00 01 	mov    BYTE PTR [rip+0x2d35],0x1        # 40a8 <stderr@GLIBC_2.2.5+0x8>
    1373:	5d                   	pop    rbp
    1374:	c3                   	ret
    1375:	0f 1f 00             	nop    DWORD PTR [rax]
    1378:	c3                   	ret
    1379:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1380:	f3 0f 1e fa          	endbr64
    1384:	e9 77 ff ff ff       	jmp    1300 <fopen@plt+0x150>
    1389:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1390:	f3 0f 1e fa          	endbr64
    1394:	c3                   	ret
    1395:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    139c:	00 00 00 00 
    13a0:	41 54                	push   r12
    13a2:	49 89 fc             	mov    r12,rdi
    13a5:	55                   	push   rbp
    13a6:	48 89 f5             	mov    rbp,rsi
    13a9:	53                   	push   rbx
    13aa:	31 db                	xor    ebx,ebx
    13ac:	eb 0a                	jmp    13b8 <fopen@plt+0x208>
    13ae:	66 90                	xchg   ax,ax
    13b0:	48 01 c3             	add    rbx,rax
    13b3:	48 39 eb             	cmp    rbx,rbp
    13b6:	73 28                	jae    13e0 <fopen@plt+0x230>
    13b8:	48 89 ea             	mov    rdx,rbp
    13bb:	31 ff                	xor    edi,edi
    13bd:	49 8d 34 1c          	lea    rsi,[r12+rbx*1]
    13c1:	48 29 da             	sub    rdx,rbx
    13c4:	e8 97 fd ff ff       	call   1160 <read@plt>
    13c9:	48 85 c0             	test   rax,rax
    13cc:	7f e2                	jg     13b0 <fopen@plt+0x200>
    13ce:	5b                   	pop    rbx
    13cf:	b8 ff ff ff ff       	mov    eax,0xffffffff
    13d4:	5d                   	pop    rbp
    13d5:	41 5c                	pop    r12
    13d7:	c3                   	ret
    13d8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
    13df:	00 
    13e0:	5b                   	pop    rbx
    13e1:	31 c0                	xor    eax,eax
    13e3:	5d                   	pop    rbp
    13e4:	41 5c                	pop    r12
    13e6:	c3                   	ret
    13e7:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
    13ee:	00 00 
    13f0:	55                   	push   rbp
    13f1:	48 89 fd             	mov    rbp,rdi
    13f4:	53                   	push   rbx
    13f5:	48 89 f3             	mov    rbx,rsi
    13f8:	be 02 00 00 00       	mov    esi,0x2
    13fd:	48 83 ec 18          	sub    rsp,0x18
    1401:	48 8d 7c 24 0e       	lea    rdi,[rsp+0xe]
    1406:	e8 95 ff ff ff       	call   13a0 <fopen@plt+0x1f0>
    140b:	85 c0                	test   eax,eax
    140d:	78 31                	js     1440 <fopen@plt+0x290>
    140f:	0f b7 54 24 0e       	movzx  edx,WORD PTR [rsp+0xe]
    1414:	89 d6                	mov    esi,edx
    1416:	66 c1 c6 08          	rol    si,0x8
    141a:	66 89 33             	mov    WORD PTR [rbx],si
    141d:	66 81 fe 00 10       	cmp    si,0x1000
    1422:	77 1c                	ja     1440 <fopen@plt+0x290>
    1424:	31 c0                	xor    eax,eax
    1426:	66 85 d2             	test   dx,dx
    1429:	74 0b                	je     1436 <fopen@plt+0x286>
    142b:	0f b7 f6             	movzx  esi,si
    142e:	48 89 ef             	mov    rdi,rbp
    1431:	e8 6a ff ff ff       	call   13a0 <fopen@plt+0x1f0>
    1436:	48 83 c4 18          	add    rsp,0x18
    143a:	5b                   	pop    rbx
    143b:	5d                   	pop    rbp
    143c:	c3                   	ret
    143d:	0f 1f 00             	nop    DWORD PTR [rax]
    1440:	b8 ff ff ff ff       	mov    eax,0xffffffff
    1445:	eb ef                	jmp    1436 <fopen@plt+0x286>
    1447:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
    144e:	00 00 
    1450:	41 56                	push   r14
    1452:	89 f0                	mov    eax,esi
    1454:	49 89 fe             	mov    r14,rdi
    1457:	41 55                	push   r13
    1459:	66 c1 c0 08          	rol    ax,0x8
    145d:	41 89 f5             	mov    r13d,esi
    1460:	41 54                	push   r12
    1462:	55                   	push   rbp
    1463:	bd 02 00 00 00       	mov    ebp,0x2
    1468:	53                   	push   rbx
    1469:	31 db                	xor    ebx,ebx
    146b:	48 83 ec 10          	sub    rsp,0x10
    146f:	66 89 44 24 0e       	mov    WORD PTR [rsp+0xe],ax
    1474:	4c 8d 64 24 0e       	lea    r12,[rsp+0xe]
    1479:	eb 0e                	jmp    1489 <fopen@plt+0x2d9>
    147b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1480:	48 01 c3             	add    rbx,rax
    1483:	48 83 fb 01          	cmp    rbx,0x1
    1487:	75 2f                	jne    14b8 <fopen@plt+0x308>
    1489:	48 89 ea             	mov    rdx,rbp
    148c:	49 8d 34 1c          	lea    rsi,[r12+rbx*1]
    1490:	bf 01 00 00 00       	mov    edi,0x1
    1495:	48 29 da             	sub    rdx,rbx
    1498:	e8 83 fc ff ff       	call   1120 <write@plt>
    149d:	48 85 c0             	test   rax,rax
    14a0:	7f de                	jg     1480 <fopen@plt+0x2d0>
    14a2:	48 83 c4 10          	add    rsp,0x10
    14a6:	b8 ff ff ff ff       	mov    eax,0xffffffff
    14ab:	5b                   	pop    rbx
    14ac:	5d                   	pop    rbp
    14ad:	41 5c                	pop    r12
    14af:	41 5d                	pop    r13
    14b1:	41 5e                	pop    r14
    14b3:	c3                   	ret
    14b4:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    14b8:	66 45 85 ed          	test   r13w,r13w
    14bc:	75 12                	jne    14d0 <fopen@plt+0x320>
    14be:	48 83 c4 10          	add    rsp,0x10
    14c2:	31 c0                	xor    eax,eax
    14c4:	5b                   	pop    rbx
    14c5:	5d                   	pop    rbp
    14c6:	41 5c                	pop    r12
    14c8:	41 5d                	pop    r13
    14ca:	41 5e                	pop    r14
    14cc:	c3                   	ret
    14cd:	0f 1f 00             	nop    DWORD PTR [rax]
    14d0:	45 0f b7 ed          	movzx  r13d,r13w
    14d4:	31 db                	xor    ebx,ebx
    14d6:	eb 10                	jmp    14e8 <fopen@plt+0x338>
    14d8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
    14df:	00 
    14e0:	48 01 c3             	add    rbx,rax
    14e3:	4c 39 eb             	cmp    rbx,r13
    14e6:	73 d6                	jae    14be <fopen@plt+0x30e>
    14e8:	4c 89 ea             	mov    rdx,r13
    14eb:	49 8d 34 1e          	lea    rsi,[r14+rbx*1]
    14ef:	bf 01 00 00 00       	mov    edi,0x1
    14f4:	48 29 da             	sub    rdx,rbx
    14f7:	e8 24 fc ff ff       	call   1120 <write@plt>
    14fc:	48 85 c0             	test   rax,rax
    14ff:	7f df                	jg     14e0 <fopen@plt+0x330>
    1501:	eb 9f                	jmp    14a2 <fopen@plt+0x2f2>
    1503:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    150a:	00 00 00 00 
    150e:	66 90                	xchg   ax,ax
    1510:	55                   	push   rbp
    1511:	53                   	push   rbx
    1512:	48 81 ec 00 10 00 00 	sub    rsp,0x1000
    1519:	48 83 0c 24 00       	or     QWORD PTR [rsp],0x0
    151e:	48 83 ec 18          	sub    rsp,0x18
    1522:	64 48 8b 14 25 28 00 	mov    rdx,QWORD PTR fs:0x28
    1529:	00 00 
    152b:	48 89 94 24 08 10 00 	mov    QWORD PTR [rsp+0x1008],rdx
    1532:	00 
    1533:	31 d2                	xor    edx,edx
    1535:	66 81 fe 00 10       	cmp    si,0x1000
    153a:	0f 87 15 01 00 00    	ja     1655 <fopen@plt+0x4a5>
    1540:	49 89 e1             	mov    r9,rsp
    1543:	0f b7 d6             	movzx  edx,si
    1546:	89 f0                	mov    eax,esi
    1548:	41 89 f0             	mov    r8d,esi
    154b:	4d 89 ca             	mov    r10,r9
    154e:	48 89 fe             	mov    rsi,rdi
    1551:	83 fa 08             	cmp    edx,0x8
    1554:	72 10                	jb     1566 <fopen@plt+0x3b6>
    1556:	48 89 d1             	mov    rcx,rdx
    1559:	4c 89 cf             	mov    rdi,r9
    155c:	48 c1 e9 03          	shr    rcx,0x3
    1560:	f3 48 a5             	rep movs QWORD PTR [rdi],QWORD PTR [rsi]
    1563:	49 89 fa             	mov    r10,rdi
    1566:	31 c9                	xor    ecx,ecx
    1568:	f6 c2 04             	test   dl,0x4
    156b:	0f 85 cf 00 00 00    	jne    1640 <fopen@plt+0x490>
    1571:	f6 c2 02             	test   dl,0x2
    1574:	0f 85 a6 00 00 00    	jne    1620 <fopen@plt+0x470>
    157a:	83 e2 01             	and    edx,0x1
    157d:	0f 85 8d 00 00 00    	jne    1610 <fopen@plt+0x460>
    1583:	0f b7 d8             	movzx  ebx,ax
    1586:	66 85 c0             	test   ax,ax
    1589:	74 57                	je     15e2 <fopen@plt+0x432>
    158b:	44 8b 1d 32 2d 00 00 	mov    r11d,DWORD PTR [rip+0x2d32]        # 42c4 <stderr@GLIBC_2.2.5+0x224>
    1592:	4c 89 c9             	mov    rcx,r9
    1595:	31 d2                	xor    edx,edx
    1597:	48 8d 2d a2 0a 00 00 	lea    rbp,[rip+0xaa2]        # 2040 <fopen@plt+0xe90>
    159e:	4c 8d 15 2b 2d 00 00 	lea    r10,[rip+0x2d2b]        # 42d0 <stderr@GLIBC_2.2.5+0x230>
    15a5:	44 89 df             	mov    edi,r11d
    15a8:	44 29 cf             	sub    edi,r9d
    15ab:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    15b0:	48 89 d6             	mov    rsi,rdx
    15b3:	8d 04 0f             	lea    eax,[rdi+rcx*1]
    15b6:	83 e6 0f             	and    esi,0xf
    15b9:	41 02 04 32          	add    al,BYTE PTR [r10+rsi*1]
    15bd:	0f b6 c0             	movzx  eax,al
    15c0:	0f b6 44 05 00       	movzx  eax,BYTE PTR [rbp+rax*1+0x0]
    15c5:	30 01                	xor    BYTE PTR [rcx],al
    15c7:	0f b7 c2             	movzx  eax,dx
    15ca:	83 c2 01             	add    edx,0x1
    15cd:	48 83 c1 01          	add    rcx,0x1
    15d1:	66 41 39 d0          	cmp    r8w,dx
    15d5:	75 d9                	jne    15b0 <fopen@plt+0x400>
    15d7:	41 8d 44 03 01       	lea    eax,[r11+rax*1+0x1]
    15dc:	89 05 e2 2c 00 00    	mov    DWORD PTR [rip+0x2ce2],eax        # 42c4 <stderr@GLIBC_2.2.5+0x224>
    15e2:	89 de                	mov    esi,ebx
    15e4:	4c 89 cf             	mov    rdi,r9
    15e7:	e8 64 fe ff ff       	call   1450 <fopen@plt+0x2a0>
    15ec:	48 8b 94 24 08 10 00 	mov    rdx,QWORD PTR [rsp+0x1008]
    15f3:	00 
    15f4:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
    15fb:	00 00 
    15fd:	75 5d                	jne    165c <fopen@plt+0x4ac>
    15ff:	48 81 c4 18 10 00 00 	add    rsp,0x1018
    1606:	5b                   	pop    rbx
    1607:	5d                   	pop    rbp
    1608:	c3                   	ret
    1609:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1610:	0f b6 14 0e          	movzx  edx,BYTE PTR [rsi+rcx*1]
    1614:	41 88 14 0a          	mov    BYTE PTR [r10+rcx*1],dl
    1618:	e9 66 ff ff ff       	jmp    1583 <fopen@plt+0x3d3>
    161d:	0f 1f 00             	nop    DWORD PTR [rax]
    1620:	0f b7 3c 0e          	movzx  edi,WORD PTR [rsi+rcx*1]
    1624:	66 41 89 3c 0a       	mov    WORD PTR [r10+rcx*1],di
    1629:	48 83 c1 02          	add    rcx,0x2
    162d:	83 e2 01             	and    edx,0x1
    1630:	0f 84 4d ff ff ff    	je     1583 <fopen@plt+0x3d3>
    1636:	eb d8                	jmp    1610 <fopen@plt+0x460>
    1638:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
    163f:	00 
    1640:	8b 0e                	mov    ecx,DWORD PTR [rsi]
    1642:	41 89 0a             	mov    DWORD PTR [r10],ecx
    1645:	b9 04 00 00 00       	mov    ecx,0x4
    164a:	f6 c2 02             	test   dl,0x2
    164d:	0f 84 27 ff ff ff    	je     157a <fopen@plt+0x3ca>
    1653:	eb cb                	jmp    1620 <fopen@plt+0x470>
    1655:	b8 ff ff ff ff       	mov    eax,0xffffffff
    165a:	eb 90                	jmp    15ec <fopen@plt+0x43c>
    165c:	e8 df fa ff ff       	call   1140 <__stack_chk_fail@plt>
    1661:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
    1668:	00 00 00 00 
    166c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    1670:	41 56                	push   r14
    1672:	41 55                	push   r13
    1674:	41 54                	push   r12
    1676:	55                   	push   rbp
    1677:	53                   	push   rbx
    1678:	48 81 ec 00 10 00 00 	sub    rsp,0x1000
    167f:	48 83 0c 24 00       	or     QWORD PTR [rsp],0x0
    1684:	48 83 ec 50          	sub    rsp,0x50
    1688:	48 8d 35 75 09 00 00 	lea    rsi,[rip+0x975]        # 2004 <fopen@plt+0xe54>
    168f:	48 8d 3d 70 09 00 00 	lea    rdi,[rip+0x970]        # 2006 <fopen@plt+0xe56>
    1696:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    169d:	00 00 
    169f:	48 89 84 24 48 10 00 	mov    QWORD PTR [rsp+0x1048],rax
    16a6:	00 
    16a7:	31 c0                	xor    eax,eax
    16a9:	e8 02 fb ff ff       	call   11b0 <fopen@plt>
    16ae:	48 85 c0             	test   rax,rax
    16b1:	0f 84 f9 01 00 00    	je     18b0 <fopen@plt+0x700>
    16b7:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
    16bc:	48 89 c1             	mov    rcx,rax
    16bf:	ba 10 00 00 00       	mov    edx,0x10
    16c4:	48 89 c3             	mov    rbx,rax
    16c7:	be 01 00 00 00       	mov    esi,0x1
    16cc:	e8 3f fa ff ff       	call   1110 <fread@plt>
    16d1:	48 89 df             	mov    rdi,rbx
    16d4:	48 83 f8 10          	cmp    rax,0x10
    16d8:	0f 85 0e 02 00 00    	jne    18ec <fopen@plt+0x73c>
    16de:	e8 4d fa ff ff       	call   1130 <fclose@plt>
    16e3:	48 8d 5c 24 40       	lea    rbx,[rsp+0x40]
    16e8:	66 0f 6f 4c 24 10    	movdqa xmm1,XMMWORD PTR [rsp+0x10]
    16ee:	be 11 00 00 00       	mov    esi,0x11
    16f3:	48 89 df             	mov    rdi,rbx
    16f6:	c6 44 24 40 01       	mov    BYTE PTR [rsp+0x40],0x1
    16fb:	0f 11 4c 24 41       	movups XMMWORD PTR [rsp+0x41],xmm1
    1700:	e8 4b fd ff ff       	call   1450 <fopen@plt+0x2a0>
    1705:	85 c0                	test   eax,eax
    1707:	0f 88 a3 01 00 00    	js     18b0 <fopen@plt+0x700>
    170d:	4c 8d 74 24 0c       	lea    r14,[rsp+0xc]
    1712:	48 89 df             	mov    rdi,rbx
    1715:	4c 89 f6             	mov    rsi,r14
    1718:	e8 d3 fc ff ff       	call   13f0 <fopen@plt+0x240>
    171d:	85 c0                	test   eax,eax
    171f:	0f 88 8b 01 00 00    	js     18b0 <fopen@plt+0x700>
    1725:	66 83 7c 24 0c 10    	cmp    WORD PTR [rsp+0xc],0x10
    172b:	0f 86 7f 01 00 00    	jbe    18b0 <fopen@plt+0x700>
    1731:	80 7c 24 40 02       	cmp    BYTE PTR [rsp+0x40],0x2
    1736:	0f 85 74 01 00 00    	jne    18b0 <fopen@plt+0x700>
    173c:	4c 8d 25 8d 2b 00 00 	lea    r12,[rip+0x2b8d]        # 42d0 <stderr@GLIBC_2.2.5+0x230>
    1743:	66 0f ef c0          	pxor   xmm0,xmm0
    1747:	4c 8d 6c 24 20       	lea    r13,[rsp+0x20]
    174c:	45 31 c0             	xor    r8d,r8d
    174f:	66 0f 6f 54 24 10    	movdqa xmm2,XMMWORD PTR [rsp+0x10]
    1755:	f3 0f 6f 5c 24 41    	movdqu xmm3,XMMWORD PTR [rsp+0x41]
    175b:	44 89 e6             	mov    esi,r12d
    175e:	4d 89 e9             	mov    r9,r13
    1761:	0f 29 05 68 2b 00 00 	movaps XMMWORD PTR [rip+0x2b68],xmm0        # 42d0 <stderr@GLIBC_2.2.5+0x230>
    1768:	f7 de                	neg    esi
    176a:	49 8d 7c 24 10       	lea    rdi,[r12+0x10]
    176f:	48 8d 2d ca 08 00 00 	lea    rbp,[rip+0x8ca]        # 2040 <fopen@plt+0xe90>
    1776:	0f 29 54 24 20       	movaps XMMWORD PTR [rsp+0x20],xmm2
    177b:	0f 29 5c 24 30       	movaps XMMWORD PTR [rsp+0x30],xmm3
    1780:	4c 89 c9             	mov    rcx,r9
    1783:	4c 89 e0             	mov    rax,r12
    1786:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    178d:	00 00 00 
    1790:	8d 14 06             	lea    edx,[rsi+rax*1]
    1793:	48 83 c0 01          	add    rax,0x1
    1797:	48 83 c1 01          	add    rcx,0x1
    179b:	83 e2 1f             	and    edx,0x1f
    179e:	0f b6 54 14 20       	movzx  edx,BYTE PTR [rsp+rdx*1+0x20]
    17a3:	32 50 ff             	xor    dl,BYTE PTR [rax-0x1]
    17a6:	0f b6 d2             	movzx  edx,dl
    17a9:	0f b6 54 15 00       	movzx  edx,BYTE PTR [rbp+rdx*1+0x0]
    17ae:	32 51 ff             	xor    dl,BYTE PTR [rcx-0x1]
    17b1:	c0 c2 03             	rol    dl,0x3
    17b4:	88 50 ff             	mov    BYTE PTR [rax-0x1],dl
    17b7:	48 39 c7             	cmp    rdi,rax
    17ba:	75 d4                	jne    1790 <fopen@plt+0x5e0>
    17bc:	41 83 c0 03          	add    r8d,0x3
    17c0:	49 83 c1 03          	add    r9,0x3
    17c4:	83 c6 08             	add    esi,0x8
    17c7:	41 83 f8 0c          	cmp    r8d,0xc
    17cb:	75 b3                	jne    1780 <fopen@plt+0x5d0>
    17cd:	c7 05 ed 2a 00 00 00 	mov    DWORD PTR [rip+0x2aed],0x0        # 42c4 <stderr@GLIBC_2.2.5+0x224>
    17d4:	00 00 00 
    17d7:	4c 89 f6             	mov    rsi,r14
    17da:	48 89 df             	mov    rdi,rbx
    17dd:	c7 05 d9 2a 00 00 00 	mov    DWORD PTR [rip+0x2ad9],0x0        # 42c0 <stderr@GLIBC_2.2.5+0x220>
    17e4:	00 00 00 
    17e7:	e8 04 fc ff ff       	call   13f0 <fopen@plt+0x240>
    17ec:	85 c0                	test   eax,eax
    17ee:	0f 88 bc 00 00 00    	js     18b0 <fopen@plt+0x700>
    17f4:	0f b7 74 24 0c       	movzx  esi,WORD PTR [rsp+0xc]
    17f9:	66 85 f6             	test   si,si
    17fc:	0f 84 ae 00 00 00    	je     18b0 <fopen@plt+0x700>
    1802:	44 8b 05 b7 2a 00 00 	mov    r8d,DWORD PTR [rip+0x2ab7]        # 42c0 <stderr@GLIBC_2.2.5+0x220>
    1809:	31 d2                	xor    edx,edx
    180b:	44 89 c7             	mov    edi,r8d
    180e:	29 df                	sub    edi,ebx
    1810:	48 89 d1             	mov    rcx,rdx
    1813:	8d 04 1f             	lea    eax,[rdi+rbx*1]
    1816:	83 c2 01             	add    edx,0x1
    1819:	83 e1 0f             	and    ecx,0xf
    181c:	41 02 04 0c          	add    al,BYTE PTR [r12+rcx*1]
    1820:	0f b6 c0             	movzx  eax,al
    1823:	0f b6 44 05 00       	movzx  eax,BYTE PTR [rbp+rax*1+0x0]
    1828:	30 03                	xor    BYTE PTR [rbx],al
    182a:	48 83 c3 01          	add    rbx,0x1
    182e:	66 39 d6             	cmp    si,dx
    1831:	75 dd                	jne    1810 <fopen@plt+0x660>
    1833:	8d 46 ff             	lea    eax,[rsi-0x1]
    1836:	0f b7 c0             	movzx  eax,ax
    1839:	41 8d 44 00 01       	lea    eax,[r8+rax*1+0x1]
    183e:	89 05 7c 2a 00 00    	mov    DWORD PTR [rip+0x2a7c],eax        # 42c0 <stderr@GLIBC_2.2.5+0x220>
    1844:	66 83 fe 10          	cmp    si,0x10
    1848:	76 66                	jbe    18b0 <fopen@plt+0x700>
    184a:	80 7c 24 40 03       	cmp    BYTE PTR [rsp+0x40],0x3
    184f:	75 5f                	jne    18b0 <fopen@plt+0x700>
    1851:	c6 44 24 0e 04       	mov    BYTE PTR [rsp+0xe],0x4
    1856:	31 c0                	xor    eax,eax
    1858:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
    185f:	00 
    1860:	41 0f b6 0c 04       	movzx  ecx,BYTE PTR [r12+rax*1]
    1865:	8d 50 05             	lea    edx,[rax+0x5]
    1868:	83 e2 0f             	and    edx,0xf
    186b:	41 0f b6 14 14       	movzx  edx,BYTE PTR [r12+rdx*1]
    1870:	32 54 0d 00          	xor    dl,BYTE PTR [rbp+rcx*1+0x0]
    1874:	41 88 54 05 00       	mov    BYTE PTR [r13+rax*1+0x0],dl
    1879:	48 83 c0 01          	add    rax,0x1
    187d:	48 83 f8 10          	cmp    rax,0x10
    1881:	75 dd                	jne    1860 <fopen@plt+0x6b0>
    1883:	48 8b 44 24 41       	mov    rax,QWORD PTR [rsp+0x41]
    1888:	48 8b 54 24 49       	mov    rdx,QWORD PTR [rsp+0x49]
    188d:	48 33 44 24 20       	xor    rax,QWORD PTR [rsp+0x20]
    1892:	48 33 54 24 28       	xor    rdx,QWORD PTR [rsp+0x28]
    1897:	48 09 d0             	or     rax,rdx
    189a:	74 3a                	je     18d6 <fopen@plt+0x726>
    189c:	48 8d 7c 24 0e       	lea    rdi,[rsp+0xe]
    18a1:	be 02 00 00 00       	mov    esi,0x2
    18a6:	c6 44 24 0f ff       	mov    BYTE PTR [rsp+0xf],0xff
    18ab:	e8 60 fc ff ff       	call   1510 <fopen@plt+0x360>
    18b0:	83 c8 ff             	or     eax,0xffffffff
    18b3:	48 8b 94 24 48 10 00 	mov    rdx,QWORD PTR [rsp+0x1048]
    18ba:	00 
    18bb:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
    18c2:	00 00 
    18c4:	75 2d                	jne    18f3 <fopen@plt+0x743>
    18c6:	48 81 c4 50 10 00 00 	add    rsp,0x1050
    18cd:	5b                   	pop    rbx
    18ce:	5d                   	pop    rbp
    18cf:	41 5c                	pop    r12
    18d1:	41 5d                	pop    r13
    18d3:	41 5e                	pop    r14
    18d5:	c3                   	ret
    18d6:	48 8d 7c 24 0e       	lea    rdi,[rsp+0xe]
    18db:	be 02 00 00 00       	mov    esi,0x2
    18e0:	c6 44 24 0f 00       	mov    BYTE PTR [rsp+0xf],0x0
    18e5:	e8 26 fc ff ff       	call   1510 <fopen@plt+0x360>
    18ea:	eb c7                	jmp    18b3 <fopen@plt+0x703>
    18ec:	e8 3f f8 ff ff       	call   1130 <fclose@plt>
    18f1:	eb bd                	jmp    18b0 <fopen@plt+0x700>
    18f3:	e8 48 f8 ff ff       	call   1140 <__stack_chk_fail@plt>
    18f8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
    18ff:	00 
    1900:	41 57                	push   r15
    1902:	41 56                	push   r14
    1904:	41 55                	push   r13
    1906:	41 54                	push   r12
    1908:	55                   	push   rbp
    1909:	53                   	push   rbx
    190a:	48 81 ec 00 10 00 00 	sub    rsp,0x1000
    1911:	48 83 0c 24 00       	or     QWORD PTR [rsp],0x0
    1916:	48 81 ec 00 10 00 00 	sub    rsp,0x1000
    191d:	48 83 0c 24 00       	or     QWORD PTR [rsp],0x0
    1922:	48 81 ec 00 10 00 00 	sub    rsp,0x1000
    1929:	48 83 0c 24 00       	or     QWORD PTR [rsp],0x0
    192e:	48 83 ec 48          	sub    rsp,0x48
    1932:	4c 8d 25 07 07 00 00 	lea    r12,[rip+0x707]        # 2040 <fopen@plt+0xe90>
    1939:	4c 8d 35 90 29 00 00 	lea    r14,[rip+0x2990]        # 42d0 <stderr@GLIBC_2.2.5+0x230>
    1940:	48 8d 2d d9 06 00 00 	lea    rbp,[rip+0x6d9]        # 2020 <fopen@plt+0xe70>
    1947:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    194e:	00 00 
    1950:	48 89 84 24 38 30 00 	mov    QWORD PTR [rsp+0x3038],rax
    1957:	00 
    1958:	31 c0                	xor    eax,eax
    195a:	48 8d 44 24 2c       	lea    rax,[rsp+0x2c]
    195f:	48 8d 5c 24 30       	lea    rbx,[rsp+0x30]
    1964:	48 89 44 24 08       	mov    QWORD PTR [rsp+0x8],rax
    1969:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1970:	48 8b 74 24 08       	mov    rsi,QWORD PTR [rsp+0x8]
    1975:	48 89 df             	mov    rdi,rbx
    1978:	e8 73 fa ff ff       	call   13f0 <fopen@plt+0x240>
    197d:	85 c0                	test   eax,eax
    197f:	0f 88 97 04 00 00    	js     1e1c <fopen@plt+0xc6c>
    1985:	44 0f b7 6c 24 2c    	movzx  r13d,WORD PTR [rsp+0x2c]
    198b:	66 45 85 ed          	test   r13w,r13w
    198f:	74 df                	je     1970 <fopen@plt+0x7c0>
    1991:	44 8b 0d 28 29 00 00 	mov    r9d,DWORD PTR [rip+0x2928]        # 42c0 <stderr@GLIBC_2.2.5+0x220>
    1998:	48 89 da             	mov    rdx,rbx
    199b:	31 c9                	xor    ecx,ecx
    199d:	44 89 cf             	mov    edi,r9d
    19a0:	29 df                	sub    edi,ebx
    19a2:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    19a8:	48 89 ce             	mov    rsi,rcx
    19ab:	8d 04 17             	lea    eax,[rdi+rdx*1]
    19ae:	83 c1 01             	add    ecx,0x1
    19b1:	83 e6 0f             	and    esi,0xf
    19b4:	41 02 04 36          	add    al,BYTE PTR [r14+rsi*1]
    19b8:	0f b6 c0             	movzx  eax,al
    19bb:	41 0f b6 04 04       	movzx  eax,BYTE PTR [r12+rax*1]
    19c0:	30 02                	xor    BYTE PTR [rdx],al
    19c2:	48 83 c2 01          	add    rdx,0x1
    19c6:	66 44 39 e9          	cmp    cx,r13w
    19ca:	72 dc                	jb     19a8 <fopen@plt+0x7f8>
    19cc:	41 8d 55 ff          	lea    edx,[r13-0x1]
    19d0:	0f b6 4c 24 30       	movzx  ecx,BYTE PTR [rsp+0x30]
    19d5:	44 0f b7 fa          	movzx  r15d,dx
    19d9:	43 8d 44 39 01       	lea    eax,[r9+r15*1+0x1]
    19de:	89 05 dc 28 00 00    	mov    DWORD PTR [rip+0x28dc],eax        # 42c0 <stderr@GLIBC_2.2.5+0x220>
    19e4:	8d 41 f0             	lea    eax,[rcx-0x10]
    19e7:	3c 06                	cmp    al,0x6
    19e9:	0f 87 52 04 00 00    	ja     1e41 <fopen@plt+0xc91>
    19ef:	0f b6 c0             	movzx  eax,al
    19f2:	48 63 44 85 00       	movsxd rax,DWORD PTR [rbp+rax*4+0x0]
    19f7:	48 01 e8             	add    rax,rbp
    19fa:	3e ff e0             	notrack jmp rax
    19fd:	0f 1f 00             	nop    DWORD PTR [rax]
    1a00:	48 8d 74 24 31       	lea    rsi,[rsp+0x31]
    1a05:	0f b7 d2             	movzx  edx,dx
    1a08:	b9 00 10 00 00       	mov    ecx,0x1000
    1a0d:	48 8d bc 24 30 10 00 	lea    rdi,[rsp+0x1030]
    1a14:	00 
    1a15:	48 89 54 24 18       	mov    QWORD PTR [rsp+0x18],rdx
    1a1a:	48 89 74 24 10       	mov    QWORD PTR [rsp+0x10],rsi
    1a1f:	e8 4c f7 ff ff       	call   1170 <__memcpy_chk@plt>
    1a24:	42 c6 84 3c 30 10 00 	mov    BYTE PTR [rsp+r15*1+0x1030],0x0
    1a2b:	00 00 
    1a2d:	4c 8d bc 24 30 20 00 	lea    r15,[rsp+0x2030]
    1a34:	00 
    1a35:	48 89 c7             	mov    rdi,rax
    1a38:	ff 15 82 26 00 00    	call   QWORD PTR [rip+0x2682]        # 40c0 <stderr@GLIBC_2.2.5+0x20>
    1a3e:	ba 15 00 00 00       	mov    edx,0x15
    1a43:	48 8b 74 24 10       	mov    rsi,QWORD PTR [rsp+0x10]
    1a48:	48 8d bc 24 32 20 00 	lea    rdi,[rsp+0x2032]
    1a4f:	00 
    1a50:	66 89 94 24 30 20 00 	mov    WORD PTR [rsp+0x2030],dx
    1a57:	00 
    1a58:	48 8b 54 24 18       	mov    rdx,QWORD PTR [rsp+0x18]
    1a5d:	b9 00 10 00 00       	mov    ecx,0x1000
    1a62:	e8 09 f7 ff ff       	call   1170 <__memcpy_chk@plt>
    1a67:	41 8d 75 01          	lea    esi,[r13+0x1]
    1a6b:	4c 89 ff             	mov    rdi,r15
    1a6e:	0f b7 f6             	movzx  esi,si
    1a71:	e8 9a fa ff ff       	call   1510 <fopen@plt+0x360>
    1a76:	e9 f5 fe ff ff       	jmp    1970 <fopen@plt+0x7c0>
    1a7b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    1a80:	b9 14 ff ff ff       	mov    ecx,0xffffff14
    1a85:	66 89 4c 24 2e       	mov    WORD PTR [rsp+0x2e],cx
    1a8a:	66 83 fa 01          	cmp    dx,0x1
    1a8e:	76 40                	jbe    1ad0 <fopen@plt+0x920>
    1a90:	0f b6 54 24 31       	movzx  edx,BYTE PTR [rsp+0x31]
    1a95:	0f b6 44 24 32       	movzx  eax,BYTE PTR [rsp+0x32]
    1a9a:	89 d1                	mov    ecx,edx
    1a9c:	09 c1                	or     ecx,eax
    1a9e:	80 f9 0f             	cmp    cl,0xf
    1aa1:	77 2d                	ja     1ad0 <fopen@plt+0x920>
    1aa3:	48 8d 0d 16 27 00 00 	lea    rcx,[rip+0x2716]        # 41c0 <stderr@GLIBC_2.2.5+0x120>
    1aaa:	48 c1 e0 04          	shl    rax,0x4
    1aae:	48 01 c8             	add    rax,rcx
    1ab1:	48 8b 30             	mov    rsi,QWORD PTR [rax]
    1ab4:	48 85 f6             	test   rsi,rsi
    1ab7:	74 17                	je     1ad0 <fopen@plt+0x920>
    1ab9:	48 c1 e2 04          	shl    rdx,0x4
    1abd:	48 01 d1             	add    rcx,rdx
    1ac0:	48 83 39 00          	cmp    QWORD PTR [rcx],0x0
    1ac4:	0f 84 94 03 00 00    	je     1e5e <fopen@plt+0xcae>
    1aca:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1ad0:	48 8d 7c 24 2e       	lea    rdi,[rsp+0x2e]
    1ad5:	be 02 00 00 00       	mov    esi,0x2
    1ada:	e8 31 fa ff ff       	call   1510 <fopen@plt+0x360>
    1adf:	e9 8c fe ff ff       	jmp    1970 <fopen@plt+0x7c0>
    1ae4:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    1ae8:	bf 13 ff ff ff       	mov    edi,0xffffff13
    1aed:	0f b6 44 24 31       	movzx  eax,BYTE PTR [rsp+0x31]
    1af2:	66 89 7c 24 2e       	mov    WORD PTR [rsp+0x2e],di
    1af7:	66 41 83 fd 01       	cmp    r13w,0x1
    1afc:	74 d2                	je     1ad0 <fopen@plt+0x920>
    1afe:	3c 0f                	cmp    al,0xf
    1b00:	77 ce                	ja     1ad0 <fopen@plt+0x920>
    1b02:	48 c1 e0 04          	shl    rax,0x4
    1b06:	4c 8d 2d b3 26 00 00 	lea    r13,[rip+0x26b3]        # 41c0 <stderr@GLIBC_2.2.5+0x120>
    1b0d:	49 01 c5             	add    r13,rax
    1b10:	49 8b 7d 00          	mov    rdi,QWORD PTR [r13+0x0]
    1b14:	48 85 ff             	test   rdi,rdi
    1b17:	74 b7                	je     1ad0 <fopen@plt+0x920>
    1b19:	e8 e2 f5 ff ff       	call   1100 <free@plt>
    1b1e:	66 41 83 6d 0a 01    	sub    WORD PTR [r13+0xa],0x1
    1b24:	75 0d                	jne    1b33 <fopen@plt+0x983>
    1b26:	31 f6                	xor    esi,esi
    1b28:	66 41 c7 45 08 00 00 	mov    WORD PTR [r13+0x8],0x0
    1b2f:	49 89 75 00          	mov    QWORD PTR [r13+0x0],rsi
    1b33:	c6 44 24 2f 00       	mov    BYTE PTR [rsp+0x2f],0x0
    1b38:	eb 96                	jmp    1ad0 <fopen@plt+0x920>
    1b3a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1b40:	41 b8 12 ff ff ff    	mov    r8d,0xffffff12
    1b46:	66 44 89 44 24 2e    	mov    WORD PTR [rsp+0x2e],r8w
    1b4c:	66 83 fa 03          	cmp    dx,0x3
    1b50:	0f 86 7a ff ff ff    	jbe    1ad0 <fopen@plt+0x920>
    1b56:	0f b6 44 24 31       	movzx  eax,BYTE PTR [rsp+0x31]
    1b5b:	3c 0f                	cmp    al,0xf
    1b5d:	0f 87 6d ff ff ff    	ja     1ad0 <fopen@plt+0x920>
    1b63:	48 c1 e0 04          	shl    rax,0x4
    1b67:	48 8d 15 52 26 00 00 	lea    rdx,[rip+0x2652]        # 41c0 <stderr@GLIBC_2.2.5+0x120>
    1b6e:	48 01 c2             	add    rdx,rax
    1b71:	48 8b 3a             	mov    rdi,QWORD PTR [rdx]
    1b74:	48 85 ff             	test   rdi,rdi
    1b77:	0f 84 53 ff ff ff    	je     1ad0 <fopen@plt+0x920>
    1b7d:	0f b7 44 24 32       	movzx  eax,WORD PTR [rsp+0x32]
    1b82:	66 c1 c0 08          	rol    ax,0x8
    1b86:	66 39 42 08          	cmp    WORD PTR [rdx+0x8],ax
    1b8a:	0f 82 40 ff ff ff    	jb     1ad0 <fopen@plt+0x920>
    1b90:	0f b7 d0             	movzx  edx,ax
    1b93:	83 c2 02             	add    edx,0x2
    1b96:	44 39 fa             	cmp    edx,r15d
    1b99:	0f 8d 31 ff ff ff    	jge    1ad0 <fopen@plt+0x920>
    1b9f:	0f b7 d0             	movzx  edx,ax
    1ba2:	48 8d 74 24 34       	lea    rsi,[rsp+0x34]
    1ba7:	e8 d4 f5 ff ff       	call   1180 <memcpy@plt>
    1bac:	c6 44 24 2f 00       	mov    BYTE PTR [rsp+0x2f],0x0
    1bb1:	e9 1a ff ff ff       	jmp    1ad0 <fopen@plt+0x920>
    1bb6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    1bbd:	00 00 00 
    1bc0:	41 b9 11 ff ff ff    	mov    r9d,0xffffff11
    1bc6:	0f b6 44 24 31       	movzx  eax,BYTE PTR [rsp+0x31]
    1bcb:	66 44 89 4c 24 2e    	mov    WORD PTR [rsp+0x2e],r9w
    1bd1:	66 41 83 fd 01       	cmp    r13w,0x1
    1bd6:	0f 84 f4 fe ff ff    	je     1ad0 <fopen@plt+0x920>
    1bdc:	3c 0f                	cmp    al,0xf
    1bde:	0f 87 ec fe ff ff    	ja     1ad0 <fopen@plt+0x920>
    1be4:	48 c1 e0 04          	shl    rax,0x4
    1be8:	48 8d 15 d1 25 00 00 	lea    rdx,[rip+0x25d1]        # 41c0 <stderr@GLIBC_2.2.5+0x120>
    1bef:	48 01 d0             	add    rax,rdx
    1bf2:	48 8b 30             	mov    rsi,QWORD PTR [rax]
    1bf5:	48 85 f6             	test   rsi,rsi
    1bf8:	0f 84 d2 fe ff ff    	je     1ad0 <fopen@plt+0x920>
    1bfe:	0f b7 50 08          	movzx  edx,WORD PTR [rax+0x8]
    1c02:	44 0f b7 78 08       	movzx  r15d,WORD PTR [rax+0x8]
    1c07:	48 8d bc 24 34 20 00 	lea    rdi,[rsp+0x2034]
    1c0e:	00 
    1c0f:	b9 00 04 00 00       	mov    ecx,0x400
    1c14:	66 c7 84 24 30 20 00 	mov    WORD PTR [rsp+0x2030],0x11
    1c1b:	00 11 00 
    1c1e:	4c 8d ac 24 30 20 00 	lea    r13,[rsp+0x2030]
    1c25:	00 
    1c26:	66 c1 c2 08          	rol    dx,0x8
    1c2a:	66 89 94 24 32 20 00 	mov    WORD PTR [rsp+0x2032],dx
    1c31:	00 
    1c32:	41 0f b7 d7          	movzx  edx,r15w
    1c36:	e8 35 f5 ff ff       	call   1170 <__memcpy_chk@plt>
    1c3b:	41 8d 77 04          	lea    esi,[r15+0x4]
    1c3f:	4c 89 ef             	mov    rdi,r13
    1c42:	0f b7 f6             	movzx  esi,si
    1c45:	e8 c6 f8 ff ff       	call   1510 <fopen@plt+0x360>
    1c4a:	e9 21 fd ff ff       	jmp    1970 <fopen@plt+0x7c0>
    1c4f:	90                   	nop
    1c50:	41 ba 10 ff ff ff    	mov    r10d,0xffffff10
    1c56:	66 44 89 54 24 2e    	mov    WORD PTR [rsp+0x2e],r10w
    1c5c:	66 83 fa 03          	cmp    dx,0x3
    1c60:	0f 86 6a fe ff ff    	jbe    1ad0 <fopen@plt+0x920>
    1c66:	0f b6 44 24 31       	movzx  eax,BYTE PTR [rsp+0x31]
    1c6b:	0f b7 54 24 32       	movzx  edx,WORD PTR [rsp+0x32]
    1c70:	3c 0f                	cmp    al,0xf
    1c72:	0f 87 58 fe ff ff    	ja     1ad0 <fopen@plt+0x920>
    1c78:	48 c1 e0 04          	shl    rax,0x4
    1c7c:	4c 8d 2d 3d 25 00 00 	lea    r13,[rip+0x253d]        # 41c0 <stderr@GLIBC_2.2.5+0x120>
    1c83:	49 01 c5             	add    r13,rax
    1c86:	49 83 7d 00 00       	cmp    QWORD PTR [r13+0x0],0x0
    1c8b:	0f 85 3f fe ff ff    	jne    1ad0 <fopen@plt+0x920>
    1c91:	66 c1 c2 08          	rol    dx,0x8
    1c95:	41 89 d1             	mov    r9d,edx
    1c98:	41 8d 41 ff          	lea    eax,[r9-0x1]
    1c9c:	66 3d ff 03          	cmp    ax,0x3ff
    1ca0:	0f 87 2a fe ff ff    	ja     1ad0 <fopen@plt+0x920>
    1ca6:	0f b7 c2             	movzx  eax,dx
    1ca9:	83 c0 02             	add    eax,0x2
    1cac:	44 39 f8             	cmp    eax,r15d
    1caf:	0f 8d 1b fe ff ff    	jge    1ad0 <fopen@plt+0x920>
    1cb5:	44 0f b7 fa          	movzx  r15d,dx
    1cb9:	44 89 4c 24 10       	mov    DWORD PTR [rsp+0x10],r9d
    1cbe:	4c 89 ff             	mov    rdi,r15
    1cc1:	e8 ca f4 ff ff       	call   1190 <malloc@plt>
    1cc6:	48 89 c7             	mov    rdi,rax
    1cc9:	48 85 c0             	test   rax,rax
    1ccc:	0f 84 fe fd ff ff    	je     1ad0 <fopen@plt+0x920>
    1cd2:	48 8d 74 24 34       	lea    rsi,[rsp+0x34]
    1cd7:	4c 89 f9             	mov    rcx,r15
    1cda:	4c 89 fa             	mov    rdx,r15
    1cdd:	e8 8e f4 ff ff       	call   1170 <__memcpy_chk@plt>
    1ce2:	44 8b 4c 24 10       	mov    r9d,DWORD PTR [rsp+0x10]
    1ce7:	c6 44 24 2f 00       	mov    BYTE PTR [rsp+0x2f],0x0
    1cec:	49 89 45 00          	mov    QWORD PTR [r13+0x0],rax
    1cf0:	66 45 89 4d 08       	mov    WORD PTR [r13+0x8],r9w
    1cf5:	66 41 c7 45 0a 01 00 	mov    WORD PTR [r13+0xa],0x1
    1cfc:	e9 cf fd ff ff       	jmp    1ad0 <fopen@plt+0x920>
    1d01:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1d08:	66 0f 6f 05 b0 23 00 	movdqa xmm0,XMMWORD PTR [rip+0x23b0]        # 40c0 <stderr@GLIBC_2.2.5+0x20>
    1d0f:	00 
    1d10:	66 0f 6f 0d b8 23 00 	movdqa xmm1,XMMWORD PTR [rip+0x23b8]        # 40d0 <stderr@GLIBC_2.2.5+0x30>
    1d17:	00 
    1d18:	b8 16 00 00 00       	mov    eax,0x16
    1d1d:	48 8d bc 24 30 20 00 	lea    rdi,[rsp+0x2030]
    1d24:	00 
    1d25:	66 0f 6f 15 b3 23 00 	movdqa xmm2,XMMWORD PTR [rip+0x23b3]        # 40e0 <stderr@GLIBC_2.2.5+0x40>
    1d2c:	00 
    1d2d:	66 0f 6f 1d bb 23 00 	movdqa xmm3,XMMWORD PTR [rip+0x23bb]        # 40f0 <stderr@GLIBC_2.2.5+0x50>
    1d34:	00 
    1d35:	be f2 00 00 00       	mov    esi,0xf2
    1d3a:	66 89 84 24 30 20 00 	mov    WORD PTR [rsp+0x2030],ax
    1d41:	00 
    1d42:	66 0f 6f 25 b6 23 00 	movdqa xmm4,XMMWORD PTR [rip+0x23b6]        # 4100 <stderr@GLIBC_2.2.5+0x60>
    1d49:	00 
    1d4a:	66 0f 6f 2d be 23 00 	movdqa xmm5,XMMWORD PTR [rip+0x23be]        # 4110 <stderr@GLIBC_2.2.5+0x70>
    1d51:	00 
    1d52:	0f 11 84 24 32 20 00 	movups XMMWORD PTR [rsp+0x2032],xmm0
    1d59:	00 
    1d5a:	66 0f 6f 35 be 23 00 	movdqa xmm6,XMMWORD PTR [rip+0x23be]        # 4120 <stderr@GLIBC_2.2.5+0x80>
    1d61:	00 
    1d62:	66 0f 6f 3d c6 23 00 	movdqa xmm7,XMMWORD PTR [rip+0x23c6]        # 4130 <stderr@GLIBC_2.2.5+0x90>
    1d69:	00 
    1d6a:	0f 11 8c 24 42 20 00 	movups XMMWORD PTR [rsp+0x2042],xmm1
    1d71:	00 
    1d72:	66 0f 6f 05 c6 23 00 	movdqa xmm0,XMMWORD PTR [rip+0x23c6]        # 4140 <stderr@GLIBC_2.2.5+0xa0>
    1d79:	00 
    1d7a:	66 0f 6f 0d ce 23 00 	movdqa xmm1,XMMWORD PTR [rip+0x23ce]        # 4150 <stderr@GLIBC_2.2.5+0xb0>
    1d81:	00 
    1d82:	0f 11 94 24 52 20 00 	movups XMMWORD PTR [rsp+0x2052],xmm2
    1d89:	00 
    1d8a:	0f 11 9c 24 62 20 00 	movups XMMWORD PTR [rsp+0x2062],xmm3
    1d91:	00 
    1d92:	66 0f 6f 15 c6 23 00 	movdqa xmm2,XMMWORD PTR [rip+0x23c6]        # 4160 <stderr@GLIBC_2.2.5+0xc0>
    1d99:	00 
    1d9a:	66 0f 6f 1d ce 23 00 	movdqa xmm3,XMMWORD PTR [rip+0x23ce]        # 4170 <stderr@GLIBC_2.2.5+0xd0>
    1da1:	00 
    1da2:	0f 11 a4 24 72 20 00 	movups XMMWORD PTR [rsp+0x2072],xmm4
    1da9:	00 
    1daa:	66 0f 6f 25 ce 23 00 	movdqa xmm4,XMMWORD PTR [rip+0x23ce]        # 4180 <stderr@GLIBC_2.2.5+0xe0>
    1db1:	00 
    1db2:	0f 11 ac 24 82 20 00 	movups XMMWORD PTR [rsp+0x2082],xmm5
    1db9:	00 
    1dba:	66 0f 6f 2d ce 23 00 	movdqa xmm5,XMMWORD PTR [rip+0x23ce]        # 4190 <stderr@GLIBC_2.2.5+0xf0>
    1dc1:	00 
    1dc2:	0f 11 b4 24 92 20 00 	movups XMMWORD PTR [rsp+0x2092],xmm6
    1dc9:	00 
    1dca:	66 0f 6f 35 ce 23 00 	movdqa xmm6,XMMWORD PTR [rip+0x23ce]        # 41a0 <stderr@GLIBC_2.2.5+0x100>
    1dd1:	00 
    1dd2:	0f 11 bc 24 a2 20 00 	movups XMMWORD PTR [rsp+0x20a2],xmm7
    1dd9:	00 
    1dda:	0f 11 84 24 b2 20 00 	movups XMMWORD PTR [rsp+0x20b2],xmm0
    1de1:	00 
    1de2:	0f 11 8c 24 c2 20 00 	movups XMMWORD PTR [rsp+0x20c2],xmm1
    1de9:	00 
    1dea:	0f 11 94 24 d2 20 00 	movups XMMWORD PTR [rsp+0x20d2],xmm2
    1df1:	00 
    1df2:	0f 11 9c 24 e2 20 00 	movups XMMWORD PTR [rsp+0x20e2],xmm3
    1df9:	00 
    1dfa:	0f 11 a4 24 f2 20 00 	movups XMMWORD PTR [rsp+0x20f2],xmm4
    1e01:	00 
    1e02:	0f 11 ac 24 02 21 00 	movups XMMWORD PTR [rsp+0x2102],xmm5
    1e09:	00 
    1e0a:	0f 11 b4 24 12 21 00 	movups XMMWORD PTR [rsp+0x2112],xmm6
    1e11:	00 
    1e12:	e8 f9 f6 ff ff       	call   1510 <fopen@plt+0x360>
    1e17:	e9 54 fb ff ff       	jmp    1970 <fopen@plt+0x7c0>
    1e1c:	48 8b 84 24 38 30 00 	mov    rax,QWORD PTR [rsp+0x3038]
    1e23:	00 
    1e24:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
    1e2b:	00 00 
    1e2d:	75 4a                	jne    1e79 <fopen@plt+0xcc9>
    1e2f:	48 81 c4 48 30 00 00 	add    rsp,0x3048
    1e36:	5b                   	pop    rbx
    1e37:	5d                   	pop    rbp
    1e38:	41 5c                	pop    r12
    1e3a:	41 5d                	pop    r13
    1e3c:	41 5e                	pop    r14
    1e3e:	41 5f                	pop    r15
    1e40:	c3                   	ret
    1e41:	48 8d 7c 24 2e       	lea    rdi,[rsp+0x2e]
    1e46:	be 02 00 00 00       	mov    esi,0x2
    1e4b:	88 4c 24 2e          	mov    BYTE PTR [rsp+0x2e],cl
    1e4f:	c6 44 24 2f ff       	mov    BYTE PTR [rsp+0x2f],0xff
    1e54:	e8 b7 f6 ff ff       	call   1510 <fopen@plt+0x360>
    1e59:	e9 12 fb ff ff       	jmp    1970 <fopen@plt+0x7c0>
    1e5e:	0f b7 50 08          	movzx  edx,WORD PTR [rax+0x8]
    1e62:	66 c7 41 0a 01 00    	mov    WORD PTR [rcx+0xa],0x1
    1e68:	48 89 31             	mov    QWORD PTR [rcx],rsi
    1e6b:	66 83 40 0a 01       	add    WORD PTR [rax+0xa],0x1
    1e70:	66 89 51 08          	mov    WORD PTR [rcx+0x8],dx
    1e74:	e9 ba fc ff ff       	jmp    1b33 <fopen@plt+0x983>
    1e79:	e8 c2 f2 ff ff       	call   1140 <__stack_chk_fail@plt>

Disassembly of section .fini:

0000000000001e80 <.fini>:
    1e80:	f3 0f 1e fa          	endbr64
    1e84:	48 83 ec 08          	sub    rsp,0x8
    1e88:	48 83 c4 08          	add    rsp,0x8
    1e8c:	c3                   	ret
