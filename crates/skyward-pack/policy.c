#include <stddef.h>
#include <stdint.h>
#include <sepol/policydb/policydb.h>

const char *skyward_policy_allow(
    const void *input, size_t input_len,
    const char *source_name, const char *target_name,
    const char *class_name, const char *permission_name,
    void **output, size_t *output_len)
{
    *output = NULL;
    *output_len = 0;
    policydb_t policy;
    if (policydb_init(&policy))
        return "cannot create policy database";
    // libsepol frees the database if reading fails.
    if (policydb_from_image(NULL, (void *)input, input_len, &policy))
        return "cannot read SELinux policy";

    const char *error = NULL;
    type_datum_t *source = hashtab_search(policy.p_types.table, source_name);
    type_datum_t *target = hashtab_search(policy.p_types.table, target_name);
    class_datum_t *class = hashtab_search(policy.p_classes.table, class_name);
    perm_datum_t *permission = class
        ? hashtab_search(class->permissions.table, permission_name) : NULL;
    if (!permission && class && class->comdatum)
        permission = hashtab_search(class->comdatum->permissions.table, permission_name);
    if (!source || !target || !permission ||
        permission->s.value < 1 || permission->s.value > 32) {
        error = "policy lacks the requested type, class, or permission";
        goto done;
    }
    if (source->flavor == TYPE_ATTRIB || target->flavor == TYPE_ATTRIB) {
        error = "source and target must be concrete types";
        goto done;
    }

    avtab_key_t key = {
        .source_type = source->s.value,
        .target_type = target->s.value,
        .target_class = class->s.value,
        .specified = AVTAB_ALLOWED,
    };
    avtab_datum_t added = { .data = UINT32_C(1) << (permission->s.value - 1) };
    avtab_datum_t *existing = avtab_search(&policy.te_avtab, &key);
    if (existing) {
        existing->data |= added.data;
    } else if (avtab_insert(&policy.te_avtab, &key, &added)) {
        error = "cannot add allow rule";
        goto done;
    }
    if (policydb_to_image(NULL, &policy, output, output_len))
        error = "cannot write SELinux policy";

done:
    policydb_destroy(&policy);
    return error;
}
