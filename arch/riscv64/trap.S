.section .text.trap
.align 2

# Trap frame layout must match modules/axruntime/src/trap.rs.
.set TF_RA,      0*8
.set TF_GP,      1*8
.set TF_TP,      2*8
.set TF_T0,      3*8
.set TF_T1,      4*8
.set TF_T2,      5*8
.set TF_S0,      6*8
.set TF_S1,      7*8
.set TF_A0,      8*8
.set TF_A1,      9*8
.set TF_A2,     10*8
.set TF_A3,     11*8
.set TF_A4,     12*8
.set TF_A5,     13*8
.set TF_A6,     14*8
.set TF_A7,     15*8
.set TF_S2,     16*8
.set TF_S3,     17*8
.set TF_S4,     18*8
.set TF_S5,     19*8
.set TF_S6,     20*8
.set TF_S7,     21*8
.set TF_S8,     22*8
.set TF_S9,     23*8
.set TF_S10,    24*8
.set TF_S11,    25*8
.set TF_T3,     26*8
.set TF_T4,     27*8
.set TF_T5,     28*8
.set TF_T6,     29*8
.set TF_SSTATUS,30*8
.set TF_SEPC,   31*8
.set TF_SCAUSE, 32*8
.set TF_STVAL,  33*8
.set TF_USER_SP,34*8
.set TF_PAD,    35*8
.set TF_SIZE,   36*8

.globl __trap_vector
__trap_vector:
    # Swap sp with sscratch. If sscratch is zero, we trapped from kernel.
    csrrw sp, sscratch, sp
    bnez sp, .Lfrom_user

.Lfrom_kernel:
    # Coming from kernel mode: restore sp and keep sscratch = 0.
    csrrw sp, sscratch, sp
    addi sp, sp, -TF_SIZE

    sd ra, TF_RA(sp)
    sd gp, TF_GP(sp)
    sd tp, TF_TP(sp)
    sd t0, TF_T0(sp)
    sd t1, TF_T1(sp)
    sd t2, TF_T2(sp)
    sd s0, TF_S0(sp)
    sd s1, TF_S1(sp)
    sd a0, TF_A0(sp)
    sd a1, TF_A1(sp)
    sd a2, TF_A2(sp)
    sd a3, TF_A3(sp)
    sd a4, TF_A4(sp)
    sd a5, TF_A5(sp)
    sd a6, TF_A6(sp)
    sd a7, TF_A7(sp)
    sd s2, TF_S2(sp)
    sd s3, TF_S3(sp)
    sd s4, TF_S4(sp)
    sd s5, TF_S5(sp)
    sd s6, TF_S6(sp)
    sd s7, TF_S7(sp)
    sd s8, TF_S8(sp)
    sd s9, TF_S9(sp)
    sd s10, TF_S10(sp)
    sd s11, TF_S11(sp)
    sd t3, TF_T3(sp)
    sd t4, TF_T4(sp)
    sd t5, TF_T5(sp)
    sd t6, TF_T6(sp)
    sd zero, TF_USER_SP(sp)
    j .Ltrap_common

.Lfrom_user:
    # Coming from user mode: sp is kernel stack, sscratch is user sp.
    addi sp, sp, -TF_SIZE

    sd ra, TF_RA(sp)
    sd gp, TF_GP(sp)
    sd tp, TF_TP(sp)
    sd t0, TF_T0(sp)
    sd t1, TF_T1(sp)
    sd t2, TF_T2(sp)
    sd s0, TF_S0(sp)
    sd s1, TF_S1(sp)
    sd a0, TF_A0(sp)
    sd a1, TF_A1(sp)
    sd a2, TF_A2(sp)
    sd a3, TF_A3(sp)
    sd a4, TF_A4(sp)
    sd a5, TF_A5(sp)
    sd a6, TF_A6(sp)
    sd a7, TF_A7(sp)
    sd s2, TF_S2(sp)
    sd s3, TF_S3(sp)
    sd s4, TF_S4(sp)
    sd s5, TF_S5(sp)
    sd s6, TF_S6(sp)
    sd s7, TF_S7(sp)
    sd s8, TF_S8(sp)
    sd s9, TF_S9(sp)
    sd s10, TF_S10(sp)
    sd s11, TF_S11(sp)
    sd t3, TF_T3(sp)
    sd t4, TF_T4(sp)
    sd t5, TF_T5(sp)
    sd t6, TF_T6(sp)

    csrr t0, sscratch
    sd t0, TF_USER_SP(sp)
    # Keep sscratch zero while running in kernel mode.
    csrw sscratch, zero

.Ltrap_common:
    csrr t0, sstatus
    sd t0, TF_SSTATUS(sp)
    csrr t0, sepc
    sd t0, TF_SEPC(sp)
    csrr t0, scause
    sd t0, TF_SCAUSE(sp)
    csrr t0, stval
    sd t0, TF_STVAL(sp)

    mv a0, sp
    call trap_handler

    ld t0, TF_SSTATUS(sp)
    andi t0, t0, 0x100
    bnez t0, .Lreturn_kernel

.Lreturn_user:
    ld t0, TF_USER_SP(sp)
    csrw sscratch, t0
    ld t0, TF_SEPC(sp)
    csrw sepc, t0
    ld t0, TF_SSTATUS(sp)
    csrw sstatus, t0

    ld ra, TF_RA(sp)
    ld gp, TF_GP(sp)
    ld tp, TF_TP(sp)
    ld t0, TF_T0(sp)
    ld t1, TF_T1(sp)
    ld t2, TF_T2(sp)
    ld s0, TF_S0(sp)
    ld s1, TF_S1(sp)
    ld a0, TF_A0(sp)
    ld a1, TF_A1(sp)
    ld a2, TF_A2(sp)
    ld a3, TF_A3(sp)
    ld a4, TF_A4(sp)
    ld a5, TF_A5(sp)
    ld a6, TF_A6(sp)
    ld a7, TF_A7(sp)
    ld s2, TF_S2(sp)
    ld s3, TF_S3(sp)
    ld s4, TF_S4(sp)
    ld s5, TF_S5(sp)
    ld s6, TF_S6(sp)
    ld s7, TF_S7(sp)
    ld s8, TF_S8(sp)
    ld s9, TF_S9(sp)
    ld s10, TF_S10(sp)
    ld s11, TF_S11(sp)
    ld t3, TF_T3(sp)
    ld t4, TF_T4(sp)
    ld t5, TF_T5(sp)
    ld t6, TF_T6(sp)

    addi sp, sp, TF_SIZE
    csrrw sp, sscratch, sp
    sret

.Lreturn_kernel:
    csrw sscratch, zero
    ld t0, TF_SEPC(sp)
    csrw sepc, t0
    ld t0, TF_SSTATUS(sp)
    csrw sstatus, t0

    ld ra, TF_RA(sp)
    ld gp, TF_GP(sp)
    ld tp, TF_TP(sp)
    ld t0, TF_T0(sp)
    ld t1, TF_T1(sp)
    ld t2, TF_T2(sp)
    ld s0, TF_S0(sp)
    ld s1, TF_S1(sp)
    ld a0, TF_A0(sp)
    ld a1, TF_A1(sp)
    ld a2, TF_A2(sp)
    ld a3, TF_A3(sp)
    ld a4, TF_A4(sp)
    ld a5, TF_A5(sp)
    ld a6, TF_A6(sp)
    ld a7, TF_A7(sp)
    ld s2, TF_S2(sp)
    ld s3, TF_S3(sp)
    ld s4, TF_S4(sp)
    ld s5, TF_S5(sp)
    ld s6, TF_S6(sp)
    ld s7, TF_S7(sp)
    ld s8, TF_S8(sp)
    ld s9, TF_S9(sp)
    ld s10, TF_S10(sp)
    ld s11, TF_S11(sp)
    ld t3, TF_T3(sp)
    ld t4, TF_T4(sp)
    ld t5, TF_T5(sp)
    ld t6, TF_T6(sp)

    addi sp, sp, TF_SIZE
    sret

.globl __trap_return
__trap_return:
    ld t0, TF_SSTATUS(sp)
    andi t0, t0, 0x100
    bnez t0, .Lreturn_kernel
    j .Lreturn_user
