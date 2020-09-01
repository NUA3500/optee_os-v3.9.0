/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (C) 2020, Nuvoton Technology Corporation
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#ifdef ARM64
#ifdef CFG_WITH_PAGER
#error "Pager not supported for ARM64"
#endif
#endif /*ARM64*/

#if defined(PLATFORM_FLAVOR_NUA3500)

#define GIC_BASE		0x50801000UL
#define GICC_OFFSET		0x2000
#define GICD_OFFSET		0x1000

#define UART0_BASE		0x40700000UL
#define UART0_REG_SIZE		0x1000

#define CONSOLE_UART_BASE	UART0_BASE
#define CONSOLE_BAUDRATE	115200
#define CONSOLE_UART_CLK_IN_HZ	24000000

#define DRAM0_BASE		0x80000000
#define DRAM0_SIZE		0x40000000

#else
#error "Unknown platform flavor"
#endif

#ifdef CFG_WITH_LPAE
#define MAX_XLAT_TABLES		5
#endif

#endif /*PLATFORM_CONFIG_H*/
