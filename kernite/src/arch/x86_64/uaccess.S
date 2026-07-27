.intel_syntax noprefix
.section .text

.global x86_uaccess_stac
.type x86_uaccess_stac, @function
x86_uaccess_stac:
	stac
	ret
.size x86_uaccess_stac, . - x86_uaccess_stac

.global x86_uaccess_clac
.type x86_uaccess_clac, @function
x86_uaccess_clac:
	clac
	ret
.size x86_uaccess_clac, . - x86_uaccess_clac
