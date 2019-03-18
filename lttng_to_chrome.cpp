/*
  lttng_to_chrome.cpp

  This file is part of lttng_to_chrome, a converter from LTTng/CTF to Chromium's Common Trace Format.

  Copyright (C) 2019 Klarälvdalens Datakonsult AB, a KDAB Group company, info@kdab.com
  Author: Milian Wolff <milian.wolff@kdab.com>

  Licensees holding valid commercial KDAB Hotspot licenses may use this file in
  accordance with Hotspot Commercial License Agreement provided with the Software.

  Contact info@kdab.com if any conditions of this licensing are not clear to you.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <babeltrace/babeltrace.h>
#include <babeltrace/ctf/iterator.h>
#include <babeltrace/ctf/events.h>

#include <memory>
#include <type_traits>
#include <string>
#include <vector>
#include <unordered_map>
#include <string_view>
#include <optional>
#include <cstdio>
#include <cmath>

template<typename T, typename Cleanup>
auto wrap(T* value, Cleanup cleanup)
{
    return std::unique_ptr<T, Cleanup>(value, cleanup);
}

template<typename Reader>
auto get(const bt_ctf_event *event, const bt_definition *scope, const char* name, Reader reader)
{
    auto definition = bt_ctf_get_field(event, scope, name);
    auto ret = std::optional<std::invoke_result_t<Reader, decltype(definition)>>();
    if (definition)
        ret = std::make_optional(reader(definition));
    return ret;
}

auto get_uint64(const bt_ctf_event *event, const bt_definition *scope, const char* name)
{
    return get(event, scope, name, bt_ctf_get_uint64);
}

auto get_int64(const bt_ctf_event *event, const bt_definition *scope, const char* name)
{
    return get(event, scope, name, bt_ctf_get_int64);
}

auto get_char_array(const bt_ctf_event *event, const bt_definition *scope, const char* name)
{
    return get(event, scope, name, bt_ctf_get_char_array);
}

auto get_string(const bt_ctf_event *event, const bt_definition *scope, const char* name)
{
    return get(event, scope, name, bt_ctf_get_string);
}

bool startsWith(std::string_view string, std::string_view prefix)
{
    return string.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), string.begin());
}

bool endsWith(std::string_view string, std::string_view suffix)
{
    return string.size() >= suffix.size() && std::equal(suffix.rbegin(), suffix.rend(), string.rbegin());
}

struct KMemAlloc
{
    uint64_t requested = 0;
    uint64_t allocated = 0;
};

KMemAlloc operator+(const KMemAlloc &lhs, const KMemAlloc &rhs)
{
    return {lhs.requested + rhs.requested, lhs.allocated + rhs.allocated};
}

KMemAlloc operator-(const KMemAlloc &lhs, const KMemAlloc &rhs)
{
    return {lhs.requested - rhs.requested, lhs.allocated - rhs.allocated};
}

KMemAlloc& operator+=(KMemAlloc &lhs, const KMemAlloc &rhs)
{
    lhs = lhs + rhs;
    return lhs;
}

KMemAlloc& operator-=(KMemAlloc &lhs, const KMemAlloc &rhs)
{
    lhs = lhs - rhs;
    return lhs;
}

struct Context
{
    static constexpr const uint64_t PAGE_SIZE = 4096;

    Context()
    {
        cpuToTid.reserve(32);
        tidToPid.reserve(1024);
    }

    int64_t tid(uint64_t cpuId) const
    {
        if (cpuToTid.size() <= cpuId)
            return -1;
        return cpuToTid[cpuId];
    }

    int64_t pid(int64_t tid) const
    {
        auto it = tidToPid.find(tid);
        return it == tidToPid.end() ? -1 : it->second;
    }

    void setTid(uint64_t cpuId, int64_t tid)
    {
        if (cpuToTid.size() <= cpuId)
            cpuToTid.resize(cpuId + 1);
        cpuToTid[cpuId] = tid;
    }

    void setPid(int64_t tid, int64_t pid, std::string_view name, int64_t timestamp)
    {
        tidToPid[tid] = pid;

        auto printName = [this, tid, pid, name, timestamp](const char *type)
        {
            printEvent(R"({"name": "%s", "ph": "M", "ts": %ld, "pid": %ld, "tid": %ld, "args": {"name": "%s"}})",
                       type, timestamp, pid, tid, name.data());
        };
        if (tid == pid)
            printName("process_name");
        printName("thread_name");
    }

    template<typename ...T>
    void printEvent(const char* fmt, T... args)
    {
        if (!firstEvent)
            printf(",");
        firstEvent = false;

        printf("\n    ");

        printf(fmt, args...);
    }

    void parseEvent(bt_ctf_event *event);

    enum KMemType {
        KMalloc,
        CacheAlloc,
    };
    void alloc(uint64_t ptr, const KMemAlloc &alloc, int64_t timestamp, KMemType type)
    {
        auto &hash = type == KMalloc ? kmem : kmemCached;
        auto &current = type == KMalloc ? currentAlloc : currentCached;
        hash[ptr] = alloc;
        current += alloc;
        printCount(type, timestamp);
    }

    void free(uint64_t ptr, int64_t timestamp, KMemType type)
    {
        auto &hash = type == KMalloc ? kmem : kmemCached;
        auto &current = type == KMalloc ? currentAlloc : currentCached;
        current -= hash[ptr];
        printCount(type, timestamp);
    }

    void pageAlloc(uint32_t order, int64_t timestamp)
    {
        currentKmemPages += pow(2, order);
        printCount("mm_page_alloc", currentKmemPages * PAGE_SIZE, timestamp);
    }

    void pageFree(uint32_t order, int64_t timestamp)
    {
        currentKmemPages -= pow(2, order);
        printCount("mm_page_alloc", currentKmemPages * PAGE_SIZE, timestamp);
    }

    void printCount(std::string_view name, int64_t value, int64_t timestamp)
    {
        if (firstCount) {
            printEvent(R"({"name": "process_sort_index", "ph": "M", "pid": 0, "tid": 0, "args": { "sort_index": -1 }})");
            printEvent(R"({"name": "process_name", "ph": "M", "pid": 0, "tid": 0, "args": { "name": "kernel statistics" }})");
            firstCount = false;
        }
        printEvent(R"({"name": "%s", "ph": "C", "ts": %lu, "pid": 0, "tid": 0, "args": {"value": %ld}})",
                   name.data(), timestamp, value);
    }

private:
    void printCount(KMemType type, int64_t timestamp)
    {
        const auto &current = type == KMalloc ? currentAlloc : currentCached;
        printCount(type == KMalloc ? "kmem_kmalloc_requested" : "kmem_cache_alloc_requested", current.requested, timestamp);
        printCount(type == KMalloc ? "kmem_kmalloc_allocated" : "kmem_cache_alloc_allocated", current.allocated, timestamp);
    }

    std::vector<int64_t> cpuToTid;
    std::unordered_map<int64_t, int64_t> tidToPid;
    std::unordered_map<uint64_t, KMemAlloc> kmem;
    std::unordered_map<uint64_t, KMemAlloc> kmemCached;
    KMemAlloc currentAlloc;
    KMemAlloc currentCached;
    std::unordered_map<uint64_t, uint64_t> kmemPages;
    uint64_t currentKmemPages = 0;
    bool firstEvent = true;
    bool firstCount = true;
};

struct Event
{
    Event(bt_ctf_event *event, Context *context)
        : name(bt_ctf_event_name(event))
        , timestamp(bt_ctf_get_timestamp(event))
    {
        auto stream_packet_context_scope = bt_ctf_get_top_level_scope(event, BT_STREAM_PACKET_CONTEXT);
        if (!stream_packet_context_scope)
            fprintf(stderr, "failed to get stream packet context scope\n");

        cpuId = get_uint64(event, stream_packet_context_scope, "cpu_id").value();

        tid = context->tid(cpuId);
        pid = context->pid(tid);

        auto event_fields_scope = bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS);
        if (!event_fields_scope)
            fprintf(stderr, "failed to get event fields scope\n");

        if (name == "sched_switch") {
            const auto next_tid = get_int64(event, event_fields_scope, "next_tid").value();
            context->setTid(cpuId, next_tid);
        } else if (name == "sched_process_fork") {
            const auto child_tid = get_int64(event, event_fields_scope, "child_tid").value();
            const auto child_pid = get_int64(event, event_fields_scope, "child_pid").value();
            const auto child_comm = get_char_array(event, event_fields_scope, "child_comm").value();
            context->setPid(child_tid, child_pid, child_comm, timestamp);
        } else if (name == "lttng_statedump_process_state") {
            const auto vtid = get_int64(event, event_fields_scope, "vtid").value();
            const auto vpid = get_int64(event, event_fields_scope, "vpid").value();
            const auto name = get_char_array(event, event_fields_scope, "name").value();
            context->setPid(vtid, vpid, name, timestamp);
        } else if (name == "sched_process_exec") {
            const auto tid = get_int64(event, event_fields_scope, "tid").value();
            auto filename = std::string_view(get_string(event, event_fields_scope, "filename").value());
            auto it = filename.find_last_of('/');
            if (it != filename.npos)
                filename.remove_prefix(it + 1);
            context->setPid(tid, context->pid(tid), filename, timestamp);
        } else if (name == "kmem_kmalloc" || name == "kmem_cache_alloc") {
            const auto ptr = get_uint64(event, event_fields_scope, "ptr").value();
            const auto bytes_req = get_uint64(event, event_fields_scope, "bytes_req").value();
            const auto bytes_alloc = get_uint64(event, event_fields_scope, "bytes_alloc").value();
            context->alloc(ptr, {bytes_req, bytes_alloc}, timestamp,
                           name == "kmem_kmalloc" ? Context::KMalloc : Context::CacheAlloc);
        } else if (name == "kmem_kfree" || name == "kmem_cache_free") {
            const auto ptr = get_uint64(event, event_fields_scope, "ptr").value();
            context->free(ptr, timestamp, name == "kmem_kfree" ? Context::KMalloc : Context::CacheAlloc);
        } else if (name == "power_cpu_frequency") {
            const auto state = get_uint64(event, event_fields_scope, "state").value();
            context->printCount("CPU " + std::to_string(cpuId) + " frequency", state, timestamp);
        } else if (name == "kmem_mm_page_alloc") {
            const auto order = get_uint64(event, event_fields_scope, "order").value();
            context->pageAlloc(order, timestamp);
        } else if (name == "kmem_mm_page_free") {
            const auto order = get_uint64(event, event_fields_scope, "order").value();
            context->pageFree(order, timestamp);
        }

        auto removeSuffix = [this](std::string_view suffix)
        {
            if (!endsWith(name, suffix))
                return false;
            name.remove_suffix(suffix.length());
            return true;
        };

        auto rewriteName = [this](std::string_view prefix, std::string_view replacement)
        {
            if (!startsWith(name, prefix))
                return false;

            mutatedName = replacement;
            mutatedName += name.substr(prefix.size());
            name = mutatedName;
            return true;
        };

        if (removeSuffix("_entry") || rewriteName("syscall_entry_", "syscall_"))
            type = 'B';
        else if (removeSuffix("_exit") || rewriteName("syscall_exit_", "syscall_"))
            type = 'E';

        // TODO: also parse /sys/kernel/debug/tracing/available_events if accessible
        const auto prefixes = {
            "block"
            "irq",
            "kmem",
            "lttng_statedump",
            "power",
            "random",
            "rcu",
            "sched",
            "scsi",
            "signal",
            "skb",
            "syscall",
            "timer",
            "workqueue",
            "writeback",
            "x86_exceptions_page_fault",
            "x86_irq_vectors",
        };
        for (auto prefix : prefixes) {
            if (startsWith(name, prefix)) {
                category = prefix;
                break;
            }
        }
    }

    std::string_view name;
    // when we rewrite the name, this is the source for the string_view
    std::string mutatedName;
    std::string_view category;
    int64_t timestamp = 0;
    uint64_t cpuId = 0;
    int64_t tid = -1;
    int64_t pid = -1;
    char type = 'i';
};

void Context::parseEvent(bt_ctf_event* ctf_event)
{
    const auto event = Event(ctf_event, this);

    if (event.category.empty()) {
        printEvent(R"({"name": "%s", "ph": "%c", "ts": %lu, "pid": %ld, "tid": %ld})",
                event.name.data(), event.type, event.timestamp, event.pid, event.tid);
    } else {
        printEvent(R"({"name": "%s", "ph": "%c", "ts": %lu, "pid": %ld, "tid": %ld, "cat": "%s"})",
                event.name.data(), event.type, event.timestamp, event.pid, event.tid, event.category.data());
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "ERROR: missing path to CTF trace\n"
                        "USAGE: lttng_to_chrome path/to/lttng/trace/folder\n");
        return 1;
    }
    auto ctx = wrap(bt_context_create(), bt_context_put);

    auto trace_id = bt_context_add_trace(ctx.get(), argv[1], "ctf", nullptr, nullptr, nullptr);
    if (trace_id < 0) {
        fprintf(stderr, "failed to open trace: %s (note: we don't recursively look for traces!)\n", argv[1]);
        return 1;
    }

    auto iter = wrap(bt_ctf_iter_create(ctx.get(), nullptr, nullptr), bt_ctf_iter_destroy);
    if (!iter) {
        fprintf(stderr, "failed to create iterator\n");
        return 1;
    }

    printf("{\n  \"displayTimeUnit\": \"ns\",  \"traceEvents\": [");

    Context context;
    do {
        auto ctf_event = bt_ctf_iter_read_event(iter.get());
        if (!ctf_event)
            break;

        try {
            context.parseEvent(ctf_event);
        } catch(const std::exception &exception) {
            fprintf(stderr, "Failed to parse event: %s\n", exception.what());
        }
    } while (bt_iter_next(bt_ctf_get_iter(iter.get())) == 0);

    printf("\n  ]\n}\n");

    return 0;
}
