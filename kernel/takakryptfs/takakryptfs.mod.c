#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x52fe1c20, "module_layout" },
	{ 0x53c0b46d, "d_path" },
	{ 0x9a1dfd65, "strpbrk" },
	{ 0x9eaca6e7, "kmem_cache_destroy" },
	{ 0xf2b1403, "kmalloc_caches" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x5becb361, "set_anon_super" },
	{ 0xaf671e91, "__set_page_dirty_nobuffers" },
	{ 0x349cba85, "strchr" },
	{ 0x7b27a9d5, "inode_permission" },
	{ 0x754d539c, "strlen" },
	{ 0x54b1fac6, "__ubsan_handle_load_invalid_value" },
	{ 0xbc0f6966, "kill_anon_super" },
	{ 0x29363f1f, "seq_puts" },
	{ 0xfe92d3e3, "deactivate_locked_super" },
	{ 0xd9b85ef6, "lockref_get" },
	{ 0x98819d29, "dput" },
	{ 0xd8912672, "seq_printf" },
	{ 0x837b7b09, "__dynamic_pr_debug" },
	{ 0xfa8cd37c, "dentry_open" },
	{ 0x99387e37, "init_user_ns" },
	{ 0x85df9b6c, "strsep" },
	{ 0xd35ca7e2, "generic_read_dir" },
	{ 0x8e3de1df, "igrab" },
	{ 0x2d39b0a7, "kstrdup" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xd0f067a6, "kern_path" },
	{ 0xfb578fc5, "memset" },
	{ 0xd83450ce, "default_llseek" },
	{ 0x1b553491, "current_task" },
	{ 0xcefb0c9f, "__mutex_init" },
	{ 0x9a5862f4, "sget" },
	{ 0x9166fada, "strncpy" },
	{ 0x84e09e7c, "kmem_cache_free" },
	{ 0x898d233e, "set_nlink" },
	{ 0xf794d093, "setattr_copy" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x8c8569cb, "kstrtoint" },
	{ 0xce807a25, "up_write" },
	{ 0x57bc19d2, "down_write" },
	{ 0xefed7235, "fput" },
	{ 0x9f984513, "strrchr" },
	{ 0x691c3702, "kmem_cache_alloc" },
	{ 0xb0310116, "generic_file_mmap" },
	{ 0x7b74a53f, "truncate_inode_pages_final" },
	{ 0xfc73d070, "simple_setattr" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x92997ed8, "_printk" },
	{ 0xa6f5a5d4, "deactivate_super" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xe36faaac, "path_put" },
	{ 0xdd41dcc4, "kmem_cache_alloc_trace" },
	{ 0x4cf7ee88, "kmem_cache_create" },
	{ 0x78060bb8, "register_filesystem" },
	{ 0x9b10228d, "iter_file_splice_write" },
	{ 0xae29f97c, "iput" },
	{ 0x37a0cba, "kfree" },
	{ 0xe7d454be, "generic_permission" },
	{ 0x69acdf38, "memcpy" },
	{ 0xe7fb72dd, "d_splice_alias" },
	{ 0x557ded6a, "d_make_root" },
	{ 0xe10951f7, "unregister_filesystem" },
	{ 0xdd9b574d, "init_special_inode" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xcf09f1aa, "new_inode" },
	{ 0x5d8e78ab, "generic_file_splice_read" },
	{ 0x47ef6e62, "lookup_one_len" },
	{ 0xa8e8122d, "clear_inode" },
	{ 0xf44f2b52, "setattr_prepare" },
	{ 0xbd8b1781, "generic_fillattr" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "A2C8F8528AD61E7883E2D32");
