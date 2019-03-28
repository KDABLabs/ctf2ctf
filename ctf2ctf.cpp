/*
  ctf2ctf.cpp

  This file is part of ctf2ctf, a converter from LTTng/CTF to Chromium's Common Trace Format.

  Copyright (C) 2019 Klarälvdalens Datakonsult AB, a KDAB Group company, info@kdab.com
  Author: Milian Wolff <milian.wolff@kdab.com>

  Licensees holding valid commercial KDAB ctf2ctf licenses may use this file in
  accordance with ctf2ctf Commercial License Agreement provided with the Software.

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
#include <filesystem>
#include <iostream>
#include <iomanip>
#include <algorithm>

#include "clioptions.h"

template<typename Callback>
void findMetadataFiles(const std::filesystem::path &path, Callback &&callback)
{
    for (const auto &entry : std::filesystem::recursive_directory_iterator(path)) {
        if (entry.is_regular_file() && entry.path().filename() == "metadata")
            callback(entry.path().parent_path().c_str());
    }
}

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

template<typename Whitelist, typename Needle>
bool contains(const Whitelist &whitelist, const Needle &needle)
{
    return std::find(whitelist.begin(), whitelist.end(), needle) != whitelist.end();
}

template<typename Whitelist, typename Needle>
bool isWhitelisted(const Whitelist &whitelist, const Needle &needle)
{
    return whitelist.empty() || contains(whitelist, needle);
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

    CliOptions options;

    Context(CliOptions options)
        : options(std::move(options))
    {
        cpuToTid.reserve(32);
        tidToPid.reserve(1024);
        cpuRunning.reserve(32);
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

    void setPid(int64_t tid, int64_t pid)
    {
        tidToPid[tid] = pid;
    }

    void printName(int64_t tid, int64_t pid, std::string_view name, int64_t timestamp)
    {
        if (tid == pid) {
            if (isFilteredByProcessName(name))
                return;

            if (!options.processWhitelist.empty() && !contains(options.pidWhitelist, pid))
                options.pidWhitelist.push_back(pid); // add pid to filer to exclude events
        }

        if (isFilteredByPid(pid))
            return;

        auto printName = [this, tid, pid, name, timestamp](const char *type)
        {
            printEvent(R"({"name": "%s", "ph": "M", "ts": %ld, "pid": %ld, "tid": %ld, "args": {"name": "%.*s"}})",
                       type, timestamp, pid, tid, name.size(), name.data());
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
        printCount(CounterGroup::Memory, "mm_page_alloc", currentKmemPages * PAGE_SIZE, timestamp);
    }

    void pageFree(uint32_t order, int64_t timestamp)
    {
        currentKmemPages -= pow(2, order);
        printCount(CounterGroup::Memory, "mm_page_alloc", currentKmemPages * PAGE_SIZE, timestamp);
    }

    // swapper is the idle process on linux
    static const constexpr int64_t SWAPPER_TID = 0;

    void schedSwitch(uint64_t cpuId, int64_t prevTid, int64_t nextTid, int64_t timestamp)
    {
        if (prevTid == nextTid)
            return;

        if (cpuRunning.size() <= cpuId)
            cpuRunning.resize(cpuId, false);

        const bool wasRunning = cpuRunning[cpuId];
        const bool isRunning = nextTid != SWAPPER_TID;
        if (wasRunning != isRunning) {
            printCount(CounterGroup::CPU, "CPU utilization", std::count(cpuRunning.begin(), cpuRunning.end(), true), timestamp);
            cpuRunning[cpuId] = isRunning;
        }
    }

    void cpuFrequency(uint64_t cpuId, uint64_t frequency, int64_t timestamp)
    {
        printCount(CounterGroup::CPU, "CPU " + std::to_string(cpuId) + " frequency", frequency, timestamp);
    }

    bool isFiltered(std::string_view name) const
    {
        return std::any_of(options.exclude.begin(), options.exclude.end(), [name](const auto &pattern) {
            return name.find(pattern) != name.npos;
        });
    }

    bool isFilteredByPid(int64_t pid) const
    {
        return !isWhitelisted(options.pidWhitelist, pid)
            // when the process name filter wasn't applied yet, filter all pids
            || (options.pidWhitelist.empty() && !options.processWhitelist.empty());
    }

    bool isFilteredByProcessName(std::string_view name) const
    {
        return !isWhitelisted(options.processWhitelist, name);
    }

    void printStats(std::ostream &out) const
    {
        if (!options.enableStatistics)
            return;

        out << "Trace Data Statistics:\n\n";

        auto printSortedStats = [&out](const auto &stats) {
            auto sortedStats = stats;
            std::sort(sortedStats.begin(), sortedStats.end(), [](const auto &lhs, const auto &rhs) {
                return lhs.counter < rhs.counter;
            });
            for (const auto &entry : sortedStats)
                out << std::setw(16) << entry.counter << '\t' << entry.name << '\n';
        };

        out << "Event Stats:\n";
        printSortedStats(eventStats);

        out << "\nEvent Category Stats:\n";
        printSortedStats(categoryStats);
    }

private:
    void count(std::string_view name, std::string_view category)
    {
        if (!options.enableStatistics)
            return;

        auto count = [](auto &stats, auto name) {
            auto it = std::lower_bound(stats.begin(), stats.end(), name, [](const auto &entry, const auto &name) {
                return entry.name < name;
            });
            if (it == stats.end() || it->name != name)
                it = stats.insert(it, {std::string(name)});
            it->counter++;
        };
        count(eventStats, name);
        count(categoryStats, category.empty() ? "uncategorized" : category);
    }

    void printCount(KMemType type, int64_t timestamp)
    {
        const auto &current = type == KMalloc ? currentAlloc : currentCached;
        printCount(CounterGroup::Memory, type == KMalloc ? "kmem_kmalloc_requested" : "kmem_cache_alloc_requested",
                   current.requested, timestamp);
        printCount(CounterGroup::Memory, type == KMalloc ? "kmem_kmalloc_allocated" : "kmem_cache_alloc_allocated",
                   current.allocated, timestamp);
    }

    enum class CounterGroup {
        CPU,
        Memory,
    };
    void printCount(CounterGroup counterGroup, std::string_view name, int64_t value, int64_t timestamp)
    {
        if (isFiltered(name))
            return;

        struct GroupData {
            const char* const name;
            const int64_t id;
            bool firstCount;
        };
        static GroupData groups[] = {
            {"CPU statistics", -2, true},
            {"Memory statistics", -3, true},
        };
        const auto groupIndex = static_cast<std::underlying_type_t<CounterGroup>>(counterGroup);
        auto &group = groups[groupIndex];
        const auto groupId = group.id;
        const auto groupName = group.name;
        auto &firstCount = group.firstCount;

        count(name, groupName);

        if (firstCount) {
            printEvent(R"({"name": "process_sort_index", "ph": "M", "pid": %1$ld, "tid": %1$ld, "args": { "sort_index": %1$ld }})",
                       groupId);
            printEvent(R"({"name": "process_name", "ph": "M", "pid": %1$ld, "tid": %1$ld, "args": { "name": "%2$s" }})",
                       groupId, groupName);
            firstCount = false;
        }
        printEvent(R"({"name": "%.*s", "ph": "C", "ts": %lu, "pid": %ld, "tid": %ld, "args": {"value": %ld}})",
                   name.size(), name.data(), timestamp, groupId, groupId, value);
    }

    std::vector<int64_t> cpuToTid;
    std::unordered_map<int64_t, int64_t> tidToPid;
    std::unordered_map<uint64_t, KMemAlloc> kmem;
    std::unordered_map<uint64_t, KMemAlloc> kmemCached;
    KMemAlloc currentAlloc;
    KMemAlloc currentCached;
    std::unordered_map<uint64_t, uint64_t> kmemPages;
    uint64_t currentKmemPages = 0;
    std::vector<bool> cpuRunning;
    bool firstEvent = true;
    struct EventStats
    {
        std::string name;
        uint64_t counter = 0;
    };
    std::vector<EventStats> eventStats;
    struct CategoryStats
    {
        std::string name;
        uint64_t counter = 0;
    };
    std::vector<CategoryStats> categoryStats;
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

            const auto next_pid = context->pid(next_tid);
            const auto next_comm = get_char_array(event, event_fields_scope, "next_comm").value();
            context->printName(next_tid, next_pid, next_comm, timestamp);

            const auto prev_tid = get_int64(event, event_fields_scope, "prev_tid").value();
            context->schedSwitch(cpuId, prev_tid, next_tid, timestamp);
        } else if (name == "sched_process_fork") {
            const auto child_tid = get_int64(event, event_fields_scope, "child_tid").value();
            const auto child_pid = get_int64(event, event_fields_scope, "child_pid").value();
            context->setPid(child_tid, child_pid);

            const auto child_comm = get_char_array(event, event_fields_scope, "child_comm").value();
            context->printName(child_tid, child_pid, child_comm, timestamp);
        } else if (name == "lttng_statedump_process_state") {
            const auto cpu = get_uint64(event, event_fields_scope, "cpu").value();
            const auto vtid = get_int64(event, event_fields_scope, "vtid").value();
            const auto vpid = get_int64(event, event_fields_scope, "vpid").value();

            context->setTid(cpu, vtid);
            context->setPid(vtid, vpid);

            const auto name = get_char_array(event, event_fields_scope, "name").value();
            context->printName(vtid, vpid, name, timestamp);

            const auto state = get_int64(event, event_fields_scope, "status").value();
            if (state & 0x1 /* TASK_INTERRUPTIBLE */)
                context->schedSwitch(cpu, Context::SWAPPER_TID, vtid, timestamp);
        } else if (name == "sched_process_exec") {
            const auto tid = get_int64(event, event_fields_scope, "tid").value();
            const auto pid = context->pid(tid);
            context->setPid(tid, pid);

            auto filename = std::string_view(get_string(event, event_fields_scope, "filename").value());
            auto it = filename.find_last_of('/');
            if (it != filename.npos)
                filename.remove_prefix(it + 1);
            context->printName(tid, pid, filename, timestamp);
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
            context->cpuFrequency(cpuId, state, timestamp);
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

        auto rewriteName = [this](std::string_view needle, std::string_view replacement, bool atStart)
        {
            const auto pos = atStart ? 0 : name.find(needle);

            if (atStart && !startsWith(name, needle))
                return false;
            else if (!atStart && pos == name.npos)
                return false;

            mutatedName = name;
            mutatedName.replace(pos, needle.size(), replacement);
            name = mutatedName;
            return true;
        };

        if (removeSuffix("_entry") || rewriteName("syscall_entry_", "syscall_", true) || rewriteName("_begin_", "_", false) || rewriteName("_before_", "_", false))
            type = 'B';
        else if (removeSuffix("_exit") || rewriteName("syscall_exit_", "syscall_", true) || rewriteName("_end_", "_", false) || rewriteName("_after_", "_", false))
            type = 'E';

        // TODO: also parse /sys/kernel/debug/tracing/available_events if accessible
        static const auto prefixes = {
            "block",
            "irq",
            "jbd2",
            "kmem",
            "lttng_statedump",
            "napi",
            "net",
            "module",
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

        if (category.empty()) {
            auto colonPos = name.find(':');
            if (colonPos != name.npos)
                category = name.substr(0, colonPos);
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

    count(event.name, event.category);

    if (isFiltered(event.name) || isFilteredByPid(event.pid))
        return;

    if (event.category.empty()) {
        printEvent(R"({"name": "%.*s", "ph": "%c", "ts": %lu, "pid": %ld, "tid": %ld})",
                   event.name.size(), event.name.data(), event.type, event.timestamp, event.pid, event.tid);
    } else {
        printEvent(R"({"name": "%.*s", "ph": "%c", "ts": %lu, "pid": %ld, "tid": %ld, "cat": "%.*s"})",
                   event.name.size(), event.name.data(), event.type, event.timestamp, event.pid, event.tid,
                   event.category.size(), event.category.data());
    }
}

int main(int argc, char **argv)
{
    Context context(parseCliOptions(argc, argv));

    auto ctx = wrap(bt_context_create(), bt_context_put);

    bool hasTrace = false;
    findMetadataFiles(context.options.path, [&ctx, &hasTrace](const char *path) {
        auto trace_id = bt_context_add_trace(ctx.get(), path, "ctf", nullptr, nullptr, nullptr);
        if (trace_id < 0)
            fprintf(stderr, "failed to open trace: %s\n", path);
        else
            hasTrace = true;
    });

    if (!hasTrace)
        return 1;

    auto iter = wrap(bt_ctf_iter_create(ctx.get(), nullptr, nullptr), bt_ctf_iter_destroy);
    if (!iter) {
        fprintf(stderr, "failed to create iterator\n");
        return 1;
    }

    printf("{\n  \"displayTimeUnit\": \"ns\",  \"traceEvents\": [");

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

    context.printStats(std::cerr);

    return 0;
}
