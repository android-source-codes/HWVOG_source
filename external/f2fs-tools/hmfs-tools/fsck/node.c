/**
 * node.c
 *
 * Many parts of codes are copied from Linux kernel/fs/f2fs.
 *
 * Copyright (C) 2015 Huawei Ltd.
 * Witten by:
 *   Hou Pengyang <houpengyang@huawei.com>
 *   Liu Shuoran <liushuoran@huawei.com>
 *   Jaegeuk Kim <jaegeuk@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include "fsck.h"
#include "node.h"
#include "quotaio_cache.h"

void f2fs_alloc_nid(struct f2fs_sb_info *sbi, nid_t *nid)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	nid_t i;

	for (i = 0; i < nm_i->max_nid; i++)
		if(f2fs_test_bit(i, nm_i->nid_bitmap) == 0)
			break;

	ASSERT(i < nm_i->max_nid);
	f2fs_set_bit(i, nm_i->nid_bitmap);
	*nid = i;
}

void set_data_blkaddr(struct dnode_of_data *dn)
{
	__le32 *addr_array;
	struct f2fs_node *node_blk = dn->node_blk;
	unsigned int ofs_in_node = dn->ofs_in_node;

	addr_array = blkaddr_in_node(node_blk);
	addr_array[ofs_in_node] = cpu_to_le32(dn->data_blkaddr);
	if (dn->node_blk != dn->inode_blk)
		dn->ndirty = 1;
	else
		dn->idirty = 1;
}

/*
 * In this function, we get a new node blk, and write back
 * node_blk would be sloadd in RAM, linked by dn->node_blk
 */
block_t new_node_block(struct f2fs_sb_info *sbi,
			struct dnode_of_data *dn, unsigned int ofs)
{
	struct f2fs_node *f2fs_inode;
	struct f2fs_node *node_blk;
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	block_t blkaddr = NULL_ADDR;

	f2fs_inode = dn->inode_blk;

	node_blk = calloc(BLOCK_SZ, 1);
	ASSERT(node_blk);

	node_blk->footer.nid = cpu_to_le32(dn->nid);
	node_blk->footer.ino = f2fs_inode->footer.ino;
	node_blk->footer.flag = cpu_to_le32(ofs << OFFSET_BIT_SHIFT);
	node_blk->footer.cp_ver = ckpt->checkpoint_ver;
	set_cold_node(node_blk, S_ISDIR(le16_to_cpu(f2fs_inode->i.i_mode)));

	dn->node_blk = node_blk;
	inc_inode_blocks(dn);
	return blkaddr;
}

/*
 * get_node_path - Get the index path of pgoff_t block
 * @offset: offset in the current index node block.
 * @noffset: NO. of the index block within a file.
 * return: depth of the index path.
 *
 * By default, it sets inline_xattr and inline_data
 */
static int get_node_path(struct f2fs_node *node, long block,
				int offset[4], unsigned int noffset[4])
{
	const long direct_index = ADDRS_PER_INODE(&node->i);
	const long direct_blks = ADDRS_PER_BLOCK;
	const long dptrs_per_blk = NIDS_PER_BLOCK;
	const long indirect_blks = ADDRS_PER_BLOCK * NIDS_PER_BLOCK;
	const long dindirect_blks = indirect_blks * NIDS_PER_BLOCK;
	int n = 0;
	int level = 0;

	noffset[0] = 0;
	if (block < direct_index) {
		offset[n] = block;
		goto got;
	}

	block -= direct_index;
	if (block < direct_blks) {
		offset[n++] = NODE_DIR1_BLOCK;
		noffset[n]= 1;
		offset[n] = block;
		level = 1;
		goto got;
	}
	block -= direct_blks;
	if (block < direct_blks) {
		offset[n++] = NODE_DIR2_BLOCK;
		noffset[n] = 2;
		offset[n] = block;
		level = 1;
		goto got;
	}
	block -= direct_blks;
	if (block < indirect_blks) {
		offset[n++] = NODE_IND1_BLOCK;
		noffset[n] = 3;
		offset[n++] = block / direct_blks;
		noffset[n] = 4 + offset[n - 1];
		offset[n] = block % direct_blks;
		level = 2;
		goto got;
	}
	block -= indirect_blks;
	if (block < indirect_blks) {
		offset[n++] = NODE_IND2_BLOCK;
		noffset[n] = 4 + dptrs_per_blk;
		offset[n++] = block / direct_blks;
		noffset[n] = 5 + dptrs_per_blk + offset[n - 1];
		offset[n] = block % direct_blks;
		level = 2;
		goto got;
	}
	block -= indirect_blks;
	if (block < dindirect_blks) {
		offset[n++] = NODE_DIND_BLOCK;
		noffset[n] = 5 + (dptrs_per_blk * 2);
		offset[n++] = block / indirect_blks;
		noffset[n] = 6 + (dptrs_per_blk * 2) +
			offset[n - 1] * (dptrs_per_blk + 1);
		offset[n++] = (block / direct_blks) % dptrs_per_blk;
		noffset[n] = 7 + (dptrs_per_blk * 2) +
			offset[n - 2] * (dptrs_per_blk + 1) +
			offset[n - 1];
		offset[n] = block % direct_blks;
		level = 3;
		goto got;
	} else {
		ASSERT(0);
	}
got:
	return level;
}

int get_dnode_of_data(struct f2fs_sb_info *sbi, struct dnode_of_data *dn,
						pgoff_t index, int mode)
{
	int offset[4];
	unsigned int noffset[4];
	struct f2fs_node *parent = NULL;
	nid_t nids[4];
	block_t nblk[4];
	struct node_info ni;
	int level, i;
	int ret;

	level = get_node_path(dn->inode_blk, index, offset, noffset);

	nids[0] = dn->nid;
	parent = dn->inode_blk;
	if (level != 0)
		nids[1] = get_nid(parent, offset[0], 1);
	else
		dn->node_blk = dn->inode_blk;

	get_node_info(sbi, nids[0], &ni);
	nblk[0] = ni.blk_addr;

	for (i = 1; i <= level; i++) {
		if (!nids[i] && mode == ALLOC_NODE) {
			struct f2fs_checkpoint *cp = F2FS_CKPT(sbi);

			if (!is_set_ckpt_flags(cp, CP_UMOUNT_FLAG)) {
				c.alloc_failed = 1;
				return -EINVAL;
			}
			f2fs_alloc_nid(sbi, &nids[i]);

			dn->nid = nids[i];

			/* Function new_node_blk get a new f2fs_node blk and update*/
			/* We should make sure that dn->node_blk == NULL*/
			nblk[i] = new_node_block(sbi, dn, noffset[i]);
			set_nid(parent, offset[i - 1], nids[i], i == 1);
		} else {
			/* If Sparse file no read API, */
			struct node_info ni;

			get_node_info(sbi, nids[i], &ni);
			dn->node_blk = calloc(BLOCK_SZ, 1);
			ASSERT(dn->node_blk);

			if (c.cached_ino == ni.ino)
				ret = hmfs_grab_node_from_cache(dn->node_blk, ni.nid, ni.blk_addr);
			else
				ret = dev_read_block(dn->node_blk, ni.blk_addr);
			ASSERT(ret >= 0);

			nblk[i] = ni.blk_addr;
		}

		if (mode == ALLOC_NODE){
			/* Parent node may have changed */
			if (c.cached_ino == ni.ino)
				ret = hmfs_write_node_to_cache(parent, nblk[i - 1]);
			else
				ret = f2fs_write_node_block(sbi, parent, nblk[i - 1]);
			ASSERT(ret >= 0);
		}
		if (i != 1)
			free(parent);

		if (i < level) {
			parent = dn->node_blk;
			nids[i + 1] = get_nid(parent, offset[i], 0);
		}
	}

	dn->nid = nids[level];
	dn->ofs_in_node = offset[level];
	dn->data_blkaddr = datablock_addr(dn->node_blk, dn->ofs_in_node);
	dn->node_blkaddr = nblk[level];
	return 0;
}

int f2fs_write_node_block(struct f2fs_sb_info *sbi, struct f2fs_node *node_blk,
		block_t blk_addr)
{
	int ret;
	int type;
	nid_t nid;
	nid_t ino;
	struct f2fs_summary sum;
	struct node_info ni;

	if (blk_addr == NULL_ADDR || blk_addr == NEW_ADDR) {
		nid = le32_to_cpu(node_blk->footer.nid);
		ino = le32_to_cpu(node_blk->footer.ino);

		type = CURSEG_COLD_NODE;
		if (IS_DNODE(node_blk)) {
			type = CURSEG_HOT_NODE;
		}
		get_node_info(sbi, nid, &ni);
		set_summary(&sum, nid, 0, ni.version);
		ret = reserve_new_block(sbi, &blk_addr, &sum, type,
					IS_INODE(node_blk));
		if (ret) {
			c.alloc_failed = 1;
			return ret;
		}
		node_blk->footer.next_blkaddr =
			cpu_to_le32(next_free_blkaddr(sbi, type));

		/* update nat info */
		update_nat_blkaddr(sbi, ino, nid, blk_addr);

		set_write_stream_id(get_stream_id(type), blk_addr);
		ret = dev_write_block(node_blk, blk_addr);
		ASSERT(ret >= 0);

	} else {
		ret = f2fs_write_block(sbi, node_blk, blk_addr, 0);
	}
	return ret;
}

int f2fs_rebuild_qf_inode(struct f2fs_sb_info *sbi, int qtype)
{
	struct f2fs_node *raw_node = NULL;
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	nid_t ino = QUOTA_INO(sb, qtype);
	__u64 cp_ver = cur_cp_version(ckpt);
	int ret = 0;

	raw_node = calloc(F2FS_BLKSIZE, 1);
	if (raw_node == NULL) {
		MSG(1, "\tError: Calloc Failed for raw_node!!!\n");
		return -ENOMEM;
	}
	f2fs_init_qf_inode(sb, raw_node, qtype, time(NULL));
	if (c.feature & cpu_to_le32(F2FS_FEATURE_INODE_CHKSUM))
		raw_node->i.i_inode_checksum =
			cpu_to_le32(f2fs_inode_chksum(raw_node));

	if (is_set_ckpt_flags(ckpt, CP_CRC_RECOVERY_FLAG))
		cp_ver |= (cur_cp_crc(ckpt) << 32);
	raw_node->footer.cp_ver = cpu_to_le64(cp_ver);

	ret = f2fs_write_node_block(sbi, raw_node, NULL_ADDR);
	if (ret < 0) {
		MSG(1, "\tError: While rebuilding the quota inode to disk!\n");
		goto err_out;
	}

	f2fs_clear_bit(ino, F2FS_FSCK(sbi)->nat_area_bitmap);
	f2fs_set_bit(ino, NM_I(sbi)->nid_bitmap);
	DBG(1, "Rebuild quota inode ([%3d] ino [0x%x])\n", qtype, ino);
err_out:
	free(raw_node);
	return ret;
}