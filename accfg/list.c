// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2019 Intel Corporation. All rights reserved.

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <util/json.h>
#include <util/filter.h>
#include <json-c/json.h>
#include <json-c/json_object.h>
#include <accfg/libaccel_config.h>
#include <util/parse-options.h>
#include <ccan/array_size/array_size.h>
#include <accfg.h>
#include <string.h>

static struct util_filter_params util_param;
static struct {
	bool devices;
	bool groups;
	bool engines;
	bool wqs;
	bool idle;
	bool save_conf;
} list;

struct map_op_name {
    int op_code;
    const char *op_name;
};

#define BITMAP_SIZE 8
#define IAX_OP_CODE_NAME		\
	{0x02, "Drain"},		\
	{0x0A, "Translation Fetch"},	\
	{0x40, "Decrypt"},		\
	{0x41, "Encrypt"},		\
	{0x42, "Decompress"},		\
	{0x43, "Compress"},		\
	{0x44, "CRC64"},		\
	{0x48, "Zdecompress32"},	\
	{0x49, "Zdecompress16"},	\
	{0x4A, "Zdecompress8"},		\
	{0x4C, "Zcompress32"},		\
	{0x4D, "Zcompress16"},		\
	{0x4E, "Zcompress8"},		\
	{0x50, "Scan"},			\
	{0x51, "Set Membership"},	\
	{0x52, "Extract"},		\
	{0x53, "Select"},		\
	{0x54, "BLE Burst"},		\
	{0x55, "Find Unique"},		\
	{0x56, "Expand"}

struct map_op_name iax_op_code_name[] = {
       IAX_OP_CODE_NAME,
       {-1, NULL}
};

#define DSA_OP_CODE_NAME			\
	{0x01, "Batch"},			\
	{0x02, "Drain"},			\
	{0x03, "Memory Move"},			\
	{0x04, "Fill"},				\
	{0x05, "Compare"},			\
	{0x06, "Compare Pattern"},		\
	{0x07, "Create Delta Record"},		\
	{0x08, "Apply Delta Record"},		\
	{0x09, "Memory Copy with Dualcast"},	\
	{0x0A, "Translation Fetch"},		\
	{0x10, "CRC Generation"},		\
	{0x11, "Copy with CRC Generation"},	\
	{0x12, "DIF Check"},			\
	{0x13, "DIF Insert"},			\
	{0x14, "DIF Strip"},			\
	{0x15, "DIF Update"},			\
	{0x17, "DIX Generate"},			\
	{0x20, "Cache Flush"},			\
	{0x21, "Update Window"},		\
	{0x23, "Inter-Domain Memory Copy"},	\
	{0x24, "Inter-Domain Fill"},		\
	{0x25, "Inter-Domain Compare"},		\
	{0x26, "Inter-Domain Compare Pattern"},	\
	{0x27, "Inter-Domain Cache Flush"}

struct map_op_name dsa_op_code_name[] = {
       DSA_OP_CODE_NAME,
       {-1, NULL}
};

struct capfield {
    const char *name;
    uint16_t cap_offset;
    uint8_t bit_offset;
    uint8_t bit_width;
    uint16_t version;
};

static struct capfield dsafields[] = {
    { "minor version", 0x00, 0, 8, 0 },
    { "major version", 0x00, 8, 8, 0 },
    { "block on fault support", 0x10, 0, 1, 0 },
    { "overlapping copy support", 0x10, 1, 1, 0 },
    { "cache control support", 0x10, 2, 1, 0 },
    { "command capabilities support", 0x10, 4, 1, 0 },
    { "durable write support", 0x10, 5, 1, 0 },
    { "inter domain support", 0x10, 6, 1, 0 },
    { "translation fetch stride support", 0x10, 7, 1, 0x200 },
    { "destination readback support", 0x10, 8, 1, 0 },
    { "drain descriptor readback address support", 0x10, 9, 1, 0 },
    { "fill16 support", 0x10, 10, 1, 0 },
    { "crc64 support", 0x10, 11, 1, 0 },
    { "completion record fault info support", 0x10, 12, 1, 0 },
    { "event log support", 0x10, 13, 2, 0 },
    { "batch continuation support", 0x10, 15, 1, 0 },
    { "maximum supported transfer size", 0x10, 16, 5, 0 },
    { "maximum supported batch size", 0x10, 21, 4, 0 },
    { "interrupt message storage size", 0x10, 25, 6, 0 },
    { "configuration support", 0x10, 31, 1, 0 },
    { "event log overflow support", 0x10, 32, 1, 0x200 },
    { "batch1 support", 0x10, 52, 1, 0 },
    { "strict ordering limitation for memory destinations", 0x10, 53, 1, 0 },
    { "strict ordering limitation for peer destinations", 0x10, 54, 1, 0 },
    { "total wq size", 0x20, 0, 16, 0 },
    { "number of wqs", 0x20, 16, 8, 0 },
    { "wqcfg size", 0x20, 24, 4, 0 },
    { "shared mode support", 0x20, 48, 1, 0 },
    { "dedicated mode support", 0x20, 49, 1, 0 },
    { "wq ats support", 0x20, 50, 1, 0 },
    { "wq priority support", 0x20, 51, 1, 0 },
    { "wq occupancy support", 0x20, 52, 1, 0 },
    { "wq occupancy interrupt support", 0x20, 53, 1, 0 },
    { "wq operations configuration support", 0x20, 54, 1, 0 },
    { "wq prs support", 0x20, 55, 1, 0 },
    { "number of groups", 0x30, 0, 8, 0 },
    { "total read buffers", 0x30, 8, 8, 0 },
    { "read buffer controls support", 0x30, 16, 1, 0 },
    { "global read buffer limit support", 0x30, 17, 1, 0 },
    { "descriptors in progress limit support", 0x30, 18, 1, 0 },
    { "bandwidth limit support", 0x30, 19, 1, 0 },
    { "number of engines", 0x38, 0, 8, 0 },
    { "maximum work descriptors in progress", 0x38, 8, 8, 0x200 },
    { "maximum batch descriptors in progress", 0x38, 16, 8, 0x200 },
    { "group configuration offset", 0x60, 0, 16, 0 },
    { "wq configuration offset", 0x60, 16, 16, 0 },
    { "msi-x permissions offset", 0x60, 32, 16, 0 },
    { "ims offset", 0x60, 48, 16, 0 },
    { "perfmon offset", 0x60, 64, 16, 0 },
    { "inter domain permissions table offset", 0x60, 80, 16, 0x200 },
    { "inter domain permissions table entry type support", 0x100, 0, 2, 0x200 },
    { "inter domain permissions table size", 0x100, 8, 16, 0x200 },
    { "offset mode support", 0x100, 24, 1, 0x200 },
    { "update window suppress drain support", 0x100, 25, 1, 0x200 },
    { "idpte size", 0x100, 26, 2, 0x200 },
    { "maximum supported sgl size", 0x180, 0, 4, 0x300 },
    { "maximum supported gather reduce block size", 0x180, 4, 4, 0x300 },
    { "operations with inter domain support", 0x180, 8, 8, 0x300 },
    { "sgl formats supported", 0x180, 32, 16, 0x300 },
    { "maximum scatter gather descriptors in progress", 0x180, 48, 8, 0x300 },
    { "data types supported", 0x180, 64, 16, 0x300 },
    { "floating point data type up conversion support", 0x180, 80, 16, 0x300 },
    { "floating point data type down conversion support", 0x180, 96, 16, 0x300 },
    { "compute operations supported", 0x180, 112, 16, 0x300 },
    { "source operand negation support", 0x180, 128, 1, 0x300 },
    { "flush to zero support", 0x180, 130, 1, 0x300 },
    { "denormal as zero support", 0x180, 131, 1, 0x300 },
    { "signed integer support", 0x180, 135, 1, 0x300 },
    { "saturate integer result support", 0x180, 136, 1, 0x300 },
    { "rounding type support", 0x180, 140, 8, 0x300 },
};


static const char* get_op_name(struct map_op_name *code_name, int op_code)
{
       int i = 0;
       while (code_name[i].op_code != -1) {
               if (code_name[i].op_code == op_code) {
                       return code_name[i].op_name;
               }
               i++;
       }
       return NULL;
}

static int get_bit(struct accfg_op_cap op_cap, int bit_index)
{
       int array_index = (BITMAP_SIZE - 1) - (bit_index / 32);
       int bit_offset = bit_index % 32;

       if (bit_index < 0 || bit_index >= 256) {
               printf("Error: bit_index out of range (0-255)\n");
               return -1;
       }

       return (op_cap.bits[array_index] & (1 << bit_offset)) != 0;
}

static uint64_t listopts_to_flags(void)
{
	uint64_t flags = 0;

	if (list.idle)
		flags |= UTIL_JSON_IDLE;
	if (list.save_conf)
		flags |= UTIL_JSON_SAVE;
	return flags;
}

static struct config_save {
	const char *saved_file;
} config_save;

static int did_fail;

#define fail(fmt, ...) \
do { \
	did_fail = 1; \
	fprintf(stderr, "accfg-%s:%s:%d: " fmt, \
			VERSION, __func__, __LINE__, ##__VA_ARGS__); \
} while (0)

static struct json_object *group_to_json(struct accfg_group *group,
		uint64_t flags)
{
	struct json_object *jgroup = json_object_new_object();
	struct json_object *jobj = NULL;
	struct accfg_device *dev = NULL;
	int dpl, gpl;

	dev = accfg_group_get_device(group);

	if (!jgroup)
		return NULL;

	jobj = json_object_new_string(accfg_group_get_devname(group));
	if (!jobj)
		goto err;

	json_object_object_add(jgroup, "dev", jobj);

	if (accfg_device_get_type(dev) != ACCFG_DEVICE_IAX) {
		jobj = json_object_new_int(accfg_group_get_read_buffers_reserved(group));
		if (!jobj)
			goto err;

		json_object_object_add(jgroup, "read_buffers_reserved", jobj);
		jobj = json_object_new_int(accfg_group_get_use_read_buffer_limit(group));
		if (!jobj)
			goto err;

		json_object_object_add(jgroup, "use_read_buffer_limit", jobj);
		jobj = json_object_new_int(accfg_group_get_read_buffers_allowed(group));
		if (!jobj)
			goto err;

		json_object_object_add(jgroup, "read_buffers_allowed", jobj);
	}

	dpl = accfg_group_get_desc_progress_limit(group);
	if (dpl >= 0) {
		jobj = json_object_new_int(dpl);
		if (!jobj)
			goto err;

		json_object_object_add(jgroup, "desc_progress_limit", jobj);
	}

	gpl = accfg_group_get_batch_progress_limit(group);
	if (gpl >= 0) {
		jobj = json_object_new_int(gpl);
		if (!jobj)
			goto err;

		json_object_object_add(jgroup, "batch_progress_limit", jobj);
	}

	return jgroup;

err:
	fail("\n");
	json_object_put(jgroup);
	return NULL;
}

static bool filter_wq(struct accfg_wq *wq, struct util_filter_ctx *ctx)
{
	unsigned int i;
	bool in_group = false;
	struct json_object *jwq;
	struct list_filter_arg *lfa = ctx->list;
	struct json_object *container;
	struct accfg_device *dev = accfg_wq_get_device(wq);
	unsigned int max_groups = accfg_device_get_max_groups(dev);
	struct accfg_json_container *jc = NULL, *iter;

	list_for_each(&lfa->jdev_list, iter, list) {
		if (match_device(dev, iter))
			jc = iter;
	}
	if (!jc)
		return false;

	if (!list.idle && !accfg_wq_is_enabled(wq))
		return true;

	jwq = util_wq_to_json(wq, lfa->flags);
	if (!jwq)
		return false;

	for (i = 0; i < max_groups; i++) {
		/*
		 * Group array will be created only if group contains
		 * the wq.
		 */
		if (accfg_wq_get_group_id(wq) ==
				jc->jgroup_id[i]) {
			in_group = true;
			container = jc->jgroup_assigned[i];

			if (!jc->jwq_group[i]) {
				/* need to create wq array per group */
				jc->jwq_group[i] = json_object_new_array();
				if (!jc->jwq_group[i])
					return false;

				if (container)
					json_object_object_add(container,
							"grouped_workqueues",
							jc->jwq_group[i]);
			}

			json_object_array_add(jc->jwq_group[i], jwq);
		}
	}

	/* for the rest, add into device jobj directly */
	if (!in_group  && (lfa->flags & UTIL_JSON_IDLE)) {
		if (!jc->jwq_ungroup) {
			jc->jwq_ungroup = json_object_new_array();
			if (!jc->jwq_ungroup)
				return false;

			container = lfa->jdevice;
			json_object_object_add(container, "ungrouped workqueues",
					       jc->jwq_ungroup);
		}

		json_object_array_add(jc->jwq_ungroup, jwq);
	}

	return true;
}

static bool filter_engine(struct accfg_engine *engine,
			  struct util_filter_ctx *ctx)
{
	unsigned int i;
	bool in_group = false;
	struct json_object *jengine;
	struct list_filter_arg *lfa = ctx->list;
	struct json_object *container;
	struct accfg_device *dev = accfg_engine_get_device(engine);
	unsigned int max_groups = accfg_device_get_max_groups(dev);
	struct accfg_json_container *jc = NULL, *iter;

	if (accfg_device_get_state(dev) != ACCFG_DEVICE_ENABLED &&
			!(lfa->flags & UTIL_JSON_IDLE))
		return false;

	list_for_each(&lfa->jdev_list, iter, list) {
		if (match_device(dev, iter))
			jc = iter;
	}
	if (!jc)
		return false;

	jengine = util_engine_to_json(engine, lfa->flags);
	if (!jengine)
		return false;

	for (i = 0; i < max_groups; i++) {
		/*
		 * group array will be created only if group contains
		 * the engine
		 */
		if (accfg_engine_get_group_id(engine) ==
				jc->jgroup_id[i]) {
			in_group = true;
			container = jc->jgroup_assigned[i];

			if (!jc->jengine_group[i]) {
				/* need to create engine array per group */
				jc->jengine_group[i] =
				    json_object_new_array();
				if (!jc->jengine_group[i])
					return false;

				if (container)
					json_object_object_add(container,
						"grouped_engines",
						jc->jengine_group[i]);
			}

			json_object_array_add(jc->jengine_group[i],
					jengine);
		}
	}

	/* for the rest, add into device directly */
	if (!in_group) {
		if (!jc->jengine_ungroup) {
			jc->jengine_ungroup = json_object_new_array();
			if (!jc->jengine_ungroup)
				return false;

			container = lfa->jdevice;
			json_object_object_add(container,
					       "ungrouped_engines",
					       jc->jengine_ungroup);
		}

		json_object_array_add(jc->jengine_ungroup, jengine);
	}

	return true;
}

static bool filter_group(struct accfg_group *group,
			 struct util_filter_ctx *ctx)
{
	uint64_t group_id;
	struct list_filter_arg *lfa = ctx->list;
	struct json_object *jgroup;
	struct json_object *container = lfa->jdevice;
	struct accfg_device *dev = accfg_group_get_device(group);
	unsigned int max_groups = accfg_device_get_max_groups(dev);
	struct accfg_json_container *jc = NULL, *iter;

	list_for_each(&lfa->jdev_list, iter, list) {
		if (match_device(dev, iter))
			jc = iter;
	}
	if (!jc)
		return false;

	if (!jc->jgroups) {
		jc->jgroups = json_object_new_array();
		if (!jc->jgroups)
			return false;

		if (container)
			json_object_object_add(container, "groups",
					       jc->jgroups);
	}

	jgroup = group_to_json(group, lfa->flags);
	if (!jgroup) {
		fail("\n");
		return false;
	}

	jc->jgroup = jgroup;
	group_id = accfg_group_get_id(group);
	jc->jgroup_id[lfa->group_num % max_groups] = group_id;
	jc->jgroup_assigned[lfa->group_num % max_groups] = jgroup;
	lfa->group_num++;

	json_object_array_add(jc->jgroups, jgroup);

	return true;
}

static bool filter_device(struct accfg_device *device,
			  struct util_filter_ctx *ctx)
{
	struct list_filter_arg *lfa = ctx->list;
	struct accfg_json_container *jc;
	unsigned int max_groups;

	max_groups = accfg_device_get_max_groups(device);

	lfa->jdevice = util_device_to_json(device, lfa->flags);
	if (!lfa->jdevice)
		return false;

	jc = malloc(sizeof(struct accfg_json_container));
	if (!jc)
		return false;

	jc->jgroup_assigned = calloc(max_groups, sizeof(struct json_object *));
	if (!jc->jgroup_assigned)
		goto err_jc;

	jc->jwq_group = calloc(max_groups, sizeof(struct json_object *));
	if (!jc->jwq_group)
		goto err_jc;

	jc->jengine_group = calloc(max_groups, sizeof(struct json_object *));
	if (!jc->jengine_group)
		goto err_jc;

	jc->jgroup_id = calloc(max_groups, sizeof(int));
	if (!jc->jgroup_id)
		goto err_jc;

	jc->device_id = accfg_device_get_id(device);
	jc->device_name = accfg_device_get_devname(device);
	list_add(&lfa->jdev_list, &jc->list);

	/* a fresh container will be null */
	jc->jgroups = NULL;
	jc->jwq_ungroup = NULL;
	jc->jengine_ungroup = NULL;

	json_object_array_add(lfa->jdevices, lfa->jdevice);
	lfa->dev_num++;

	return true;
err_jc:
	free(jc);
	return false;
}

static void free_containers(struct list_filter_arg *lfa)
{
	struct accfg_json_container *jc, *next;

	list_for_each_safe(&lfa->jdev_list, jc, next, list) {
		if (!jc)
			break;
		if (jc->jgroup_assigned)
			free(jc->jgroup_assigned);
		if (jc->jwq_group)
			free(jc->jwq_group);
		if (jc->jengine_group)
			free(jc->jengine_group);
		if (jc->jgroup_id)
			free(jc->jgroup_id);
		free(jc);
	}
}

static int save_config(struct list_filter_arg *lfa, const char *saved_file)
{
	struct json_object *jdevices = lfa->jdevices;
	FILE *fd = fopen(saved_file, "w");

	if (!fd) {
		fprintf(stderr, "Failed to open %s for save: %s\n",
				saved_file, strerror(errno));
		return -EIO;
	}

	if (jdevices)
		util_display_json_array(fd, jdevices, lfa->flags);

	/* free all the allocated container data structure */
	free_containers(lfa);
	fclose(fd);

	return 0;
}

static int display_device(struct json_object *jdevices,
		struct list_filter_arg *lfa)
{
	struct json_object *jdevice;

	printf("%s\n", "devices:");
	if (!util_param.device) {
		util_display_json_array(stdout, jdevices, lfa->flags);
		return 0;
	}

	jdevice = json_object_array_get_idx(jdevices, 0);
	if (!jdevice) {
		fprintf(stderr, "No matching device found\n");
		return -EINVAL;
	}

	printf("%s\n", json_object_to_json_string_ext(jdevice,
				JSON_C_TO_STRING_PRETTY));

	return 0;
}

static int display_group(struct list_filter_arg *lfa, struct accfg_ctx *ctx)
{
	struct accfg_json_container *iter, *jc = NULL;
	struct accfg_device *dev;
	int rc;

	printf("%s\n", "groups:");

	if (!util_param.group) {
		list_for_each(&lfa->jdev_list, iter, list) {
			printf("device %s:\n", iter->device_name);
			util_display_json_array(stdout, iter->jgroups,
					lfa->flags);
		}
		return 0;

	}

	rc = parse_group_name(ctx, util_param.group, &dev, NULL);
	if (rc)
		return rc;

	list_for_each(&lfa->jdev_list, iter, list)
		if (match_device(dev, iter)) {
			jc = iter;
			break;
		}

	if (!jc) {
		fprintf(stderr, "No matching group found\n");
		return -EINVAL;
	}

	printf("device %s:\n", jc->device_name);
	if (jc->jgroups)
		util_display_json_array(stdout, jc->jgroups, lfa->flags);

	return 0;
}

static int display_wq(struct list_filter_arg *lfa, struct accfg_ctx *ctx)
{
	unsigned int max_groups, index = 0;
	struct accfg_device *dev;
	struct accfg_json_container *jc = NULL, *iter;
	int rc;

	printf("%s\n", "workqueues:");

	if (!util_param.wq) {
		list_for_each(&lfa->jdev_list, iter, list) {
			bool once = true;

			dev = accfg_ctx_device_get_by_name(ctx, iter->device_name);
			max_groups = accfg_device_get_max_groups(dev);

			printf("device %s:\n", iter->device_name);
			for (index = 0; index < max_groups; index++) {
				if (iter->jwq_group[index] != NULL) {
					if (once) {
						printf("grouped workqueues:\n");
						once = false;
					}
					printf("group id %u:\n", iter->jgroup_id[index]);
					util_display_json_array(stdout,
						iter->jwq_group[index],
						lfa->flags);
				}
			}

			if (iter->jwq_ungroup != NULL) {
				printf("ungrouped workqueues:\n");
				util_display_json_array(stdout,
						iter->jwq_ungroup,
						lfa->flags);
			}

		}
		return 0;
	}

	rc = parse_wq_name(ctx, util_param.wq, &dev, NULL);
	if (rc)
		return rc;

	max_groups = accfg_device_get_max_groups(dev);

	list_for_each(&lfa->jdev_list, iter, list)
		if (match_device(dev, iter)) {
			jc = iter;
			break;
		}
	if (!jc) {
		fprintf(stderr, "No matching workqueue found\n");
		return -EINVAL;
	}

	printf("device %s:\n", jc->device_name);
	for (index = 0; index < max_groups; index++)
		if (jc->jwq_group[index])
			util_display_json_array(stdout, jc->jwq_group[index],
					lfa->flags);
	if (jc->jwq_ungroup)
		util_display_json_array(stdout, jc->jwq_ungroup, lfa->flags);

	return 0;
}

static int display_engine(struct list_filter_arg *lfa, struct accfg_ctx *ctx)
{
	unsigned int max_groups, index = 0;
	struct accfg_device *dev;
	struct accfg_json_container *jc = NULL, *iter;
	int rc;

	printf("%s\n", "engines:");

	if (!util_param.engine) {
		list_for_each(&lfa->jdev_list, iter, list) {
			bool once = true;

			dev = accfg_ctx_device_get_by_name(ctx, iter->device_name);
			max_groups = accfg_device_get_max_groups(dev);

			printf("device %s:\n", iter->device_name);
			for (index = 0; index < max_groups; index++) {
				if (iter->jengine_group[index] != NULL) {
					if (once) {
						printf("grouped engines:\n");
						once = false;
					}
					printf("group id %u:\n", iter->jgroup_id[index]);
					util_display_json_array(stdout,
						iter->jengine_group[index],
						lfa->flags);
				}
			}

			if (iter->jengine_ungroup != NULL) {
				printf("ungrouped engines:\n");
				util_display_json_array(stdout,
						iter->jengine_ungroup,
						lfa->flags);
			}

		}
		return 0;
	}

	rc = parse_engine_name(ctx, util_param.engine, &dev, NULL);
	if (rc)
		return rc;

	max_groups = accfg_device_get_max_groups(dev);

	list_for_each(&lfa->jdev_list, iter, list)
		if (match_device(dev, iter)) {
			jc = iter;
			break;
		}
	if (!jc) {
		fprintf(stderr, "No matching engine found\n");
		return -EINVAL;
	}

	printf("device %s:\n", jc->device_name);
	for (index = 0; index < max_groups; index++)
		if (jc->jengine_group[index])
			util_display_json_array(stdout,
					jc->jengine_group[index], lfa->flags);

	if (jc->jengine_ungroup)
		util_display_json_array(stdout, jc->jengine_ungroup,
				lfa->flags);

	return 0;
}

static int list_display(struct list_filter_arg *lfa, struct accfg_ctx *ctx)
{
	struct json_object *jdevices = lfa->jdevices;

	if (!list.devices && !list.groups && !list.wqs && !list.engines) {
		if (jdevices)
			util_display_json_array(stdout, jdevices, lfa->flags);
	} else if (list.devices) {
		return display_device(jdevices, lfa);
	} else if (list.groups) {
		return display_group(lfa, ctx);
	} else if (list.wqs) {
		return display_wq(lfa, ctx);
	} else if (list.engines) {
		return display_engine(lfa, ctx);
	}

	/* free all the allocated container data structure */
	free_containers(lfa);

	return 0;
}

static int num_list_flags(void)
{
	return list.devices + list.groups + list.wqs + list.engines;
}

int cmd_list(int argc, const char **argv, void *ctx)
{
	int i, rc;

	const struct option options[] = {
		OPT_STRING('d', "device", &util_param.device, "device-id",
			   "filter by device"),
		OPT_STRING('g', "group", &util_param.group, "group-id",
			   "filter by group"),
		OPT_STRING('q', "workqueue", &util_param.wq, "wq-id",
			   "filter by workqueue"),
		OPT_STRING('e', "engine", &util_param.engine, "engine-id",
			   "filter by engine"),
		OPT_BOOLEAN('G', "groups", &list.groups,
				"include group info"),
		OPT_BOOLEAN('D', "devices", &list.devices,
			    "include device info"),
		OPT_BOOLEAN('E', "engines", &list.engines,
			    "include engine info"),
		OPT_BOOLEAN('Q', "workqueues", &list.wqs,
			    "include workqueue info"),
		OPT_BOOLEAN('i', "idle", &list.idle,
				"include idle components"),
		OPT_END(),
	};
	const char *const u[] = {
		"accel-config list [<options>]",
		NULL
	};
	struct util_filter_ctx fctx = { 0 };
	struct list_filter_arg lfa = { 0 };

	argc = parse_options(argc, argv, options, u, 0);
	for (i = 0; i < argc; i++)
		error("unknown parameter \"%s\"\n", argv[i]);

	if (argc)
		usage_with_options(u, options);

	if (num_list_flags() == 0) {
		list.devices = !!util_param.device;
		list.groups = !!util_param.group;
		list.wqs = !!util_param.wq;
		list.engines = !!util_param.engine;
	}

	lfa.jdevices = json_object_new_array();
	if (!lfa.jdevices)
		return -ENOMEM;
	list_head_init(&lfa.jdev_list);

	fctx.filter_device = filter_device;
	fctx.filter_group = filter_group;
	fctx.filter_wq = filter_wq;
	fctx.filter_engine = filter_engine;
	fctx.list = &lfa;
	lfa.flags = listopts_to_flags();

	rc = util_filter_walk(ctx, &fctx, &util_param);
	if (rc)
		return rc;

	rc = list_display(&lfa, ctx);
	if (rc)
		return rc;

	if (did_fail)
		return -EINVAL;

	return 0;
}

int cmd_info(int argc, const char **argv, void *ctx)
{
	struct map_op_name *cur_op_name = NULL;
	struct accfg_device *device;
	struct accfg_op_cap op_cap;
	union dsacap dsa_caps;

	bool verbose = false;
	const char *dev_name;
	const char *op_name;
	int rc, j, has_op;

	const struct option options[] = {
		OPT_BOOLEAN('v', "verbose", &verbose, "show more info"),
		OPT_END(),
	};
	const char *const u[] = {
		"accel-config info [<options>]",
		NULL
	};

	argc = parse_options(argc, argv, options, u, 0);
	for (j = 0; j < argc; j++)
		error("unknown parameter \"%s\"\n", argv[j]);

	accfg_device_foreach(ctx, device) {
		dev_name = accfg_device_get_devname(device);
		fprintf(stdout, "%s %s\n", dev_name,
			accfg_device_is_active(device)? "[active]" : "");

		rc = accfg_device_get_op_cap(device, &op_cap);
		if (rc) {
			printf("Error getting op cap\n");
			return rc;
		}

		for (j = 0; j < BITMAP_SIZE; j++)
			printf("%08x,", op_cap.bits[j]);
		printf("\b \n");

		if (strstr(dev_name, "dsa") != NULL) {
			printf("dsa3.0:\t");
			rc = accfg_device_get_dsa_cap(device, &dsa_caps);
			for (j = 0; j < 6; j++)
				printf("%08x,", dsa_caps.bits[j]);
			printf("\b \n");
		}

		if (!verbose)
			continue;

		if (strstr(dev_name, "dsa") != NULL) {
			cur_op_name = dsa_op_code_name;
		} else if (strstr(dev_name, "iax") != NULL) {
			cur_op_name = iax_op_code_name;
		}
		for (int k = 0; k < 256; k++) {
			has_op = get_bit(op_cap, k);
			op_name = get_op_name(cur_op_name, k);
			if (op_name)
				printf("%s[%c] ", op_name, has_op? '+' : '-');
		}
		printf("\n");
	}

	return 0;
}
int cmd_save(int argc, const char **argv, void *ctx)
{
	const struct option options[] = {
		OPT_STRING('s', "saved-file", &config_save.saved_file,
			"saved-file", "specify saved file name and path"),
		OPT_END(),
	};
	const char *const u[] = {
		"accel-config save-config [<options>]",
		NULL
	};
	struct util_filter_ctx fctx = { 0 };
	struct list_filter_arg lfa = { 0 };
	int i, rc;
	char *config_file;

	argc = parse_options(argc, argv, options, u, 0);
	for (i = 0; i < argc; i++)
		error("unknown parameter \"%s\"\n", argv[i]);

	if (argc)
		usage_with_options(u, options);

	lfa.jdevices = json_object_new_array();
	if (!lfa.jdevices)
		return -ENOMEM;
	list_head_init(&lfa.jdev_list);

	list.save_conf = true;
	fctx.filter_device = filter_device;
	fctx.filter_group = filter_group;
	fctx.filter_wq = filter_wq;
	fctx.filter_engine = filter_engine;
	fctx.list = &lfa;
	lfa.flags = listopts_to_flags();

	rc = util_filter_walk(ctx, &fctx, &util_param);
	if (rc)
		return rc;

	if (config_save.saved_file)
		config_file = strdup(config_save.saved_file);
	else
		config_file = strdup(ACCFG_CONF_FILE);
	if (!config_file) {
		fprintf(stderr, "strdup failed\n");
		return -ENOMEM;
	}

	rc = save_config(&lfa, config_file);
	free(config_file);
	if (rc < 0)
		return rc;
	return 0;
}
