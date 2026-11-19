#include <assert.h>
#define main watchdog_entry_main
#include "watchdog.c"
#undef main

/* 验证自动发现仅纳管 Selector 站点自动组，避免对 Fallback 组回弹或接管默认代理 */
static void test_auto_groups_selector_only(void) {
    Catalog cat;
    memset(&cat, 0, sizeof cat);
    Group items[] = {
        {.name = "🚀 默认代理", .type = "Selector", .now = "🤖 自动"},
        {.name = "🤖 自动", .type = "Fallback", .now = "♻️ 狮城自动"},
        {.name = "♻️ 狮城自动", .type = "Fallback", .now = "[GRC] 新加坡 A01"},
        {.name = "♻️ 美国自动", .type = "Fallback", .now = "[GRC] 美国 A02"},
        {.name = "🤖 Cursor自动", .type = "Selector", .now = "[ZLH] US | 02 | VLESS"},
        {.name = "🤖 GitHub自动", .type = "Selector", .now = "[GRC] 日本 A01"},
        {.name = "🤖 AGY 美国自动", .type = "Selector", .now = "🤖 自动"},
        {.name = "🌐 全部节点", .type = "Selector", .now = "[ZLH] US | 02 | VLESS"},
    };
    int cnt = (int)(sizeof items / sizeof items[0]);
    for (int i = 0; i < cnt; i++)
        cat.items[cat.n++] = items[i];

    char watched[MAX_WATCHED][MAX_NAME];
    int n = auto_groups(&cat, watched);
    assert(n == 2);
    assert(strcmp(watched[0], "🤖 Cursor自动") == 0);
    assert(strcmp(watched[1], "🤖 GitHub自动") == 0);
}

/* 验证默认代理走地区 Fallback 链时不会误归因给站点看门狗，显式指定时仍可定位 */
static void test_resolve_watch_group(void) {
    Catalog cat;
    memset(&cat, 0, sizeof cat);
    Group items[] = {
        {.name = "🚀 默认代理", .type = "Selector", .now = "🤖 自动"},
        {.name = "🤖 自动", .type = "Fallback", .now = "♻️ 狮城自动"},
        {.name = "♻️ 狮城自动", .type = "Fallback", .now = "[GRC] 新加坡 A01"},
        {.name = "🤖 GitHub自动", .type = "Selector", .now = "[GRC] 日本 A01"},
    };
    int cnt = (int)(sizeof items / sizeof items[0]);
    for (int i = 0; i < cnt; i++)
        cat.items[cat.n++] = items[i];

    char watched[MAX_WATCHED][MAX_NAME];
    int n = auto_groups(&cat, watched);
    assert(resolve_watch_group("🚀 默认代理", &cat, watched, n) == NULL);
    const char *hit = resolve_watch_group("🤖 GitHub自动", &cat, watched, n);
    assert(hit && strcmp(hit, "🤖 GitHub自动") == 0);

    char explicit_watch[MAX_WATCHED][MAX_NAME];
    snprintf(explicit_watch[0], MAX_NAME, "%s", "🚀 默认代理");
    const char *exp_hit = resolve_watch_group("🚀 默认代理", &cat, explicit_watch, 1);
    assert(exp_hit && strcmp(exp_hit, "🚀 默认代理") == 0);
}

/* 验证链式引用缺失错误会被识别为可切换故障，避免看门狗卡在失效节点 */
static void test_classify_missing(void) {
    assert(strcmp(classify("proxyName[ISP-0] not found"), "missing") == 0);
    assert(fail_type_ok("missing") == 1);
    assert(strcmp(classify("connection refused"), "refused") == 0);
    assert(fail_type_ok("refused") == 0);
}

int main(void) {
    test_auto_groups_selector_only();
    test_resolve_watch_group();
    test_classify_missing();
    printf("all watchdog unit tests passed\n");
    return 0;
}
