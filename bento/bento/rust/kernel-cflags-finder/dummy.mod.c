#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, "dummy");

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = "dummy",
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x9d52e3bd, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "7A661B835287E87F613DA35");
