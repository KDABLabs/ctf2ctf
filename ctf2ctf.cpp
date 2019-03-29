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
#include <babeltrace/ctf/events.h>
#include <babeltrace/ctf/iterator.h>

#include <cmath>
#include <cstdio>

#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include "clioptions.h"

#include "config.h"

#if Qt5Gui_FOUND
#include <QEvent>
#include <QMetaEnum>
#endif

constexpr auto TIMESTAMP_PRECISION = std::numeric_limits<double>::max_digits10;

template<typename Callback>
void findMetadataFiles(const std::filesystem::path& path, Callback&& callback)
{
    for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
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
auto get(const bt_ctf_event* event, const bt_definition* scope, const char* name, Reader reader)
{
    auto definition = bt_ctf_get_field(event, scope, name);
    auto ret = std::optional<std::invoke_result_t<Reader, decltype(definition)>>();
    if (definition)
        ret = std::make_optional(reader(definition));
    return ret;
}

auto get_uint64(const bt_ctf_event* event, const bt_definition* scope, const char* name)
{
    return get(event, scope, name, bt_ctf_get_uint64);
}

auto get_int64(const bt_ctf_event* event, const bt_definition* scope, const char* name)
{
    return get(event, scope, name, bt_ctf_get_int64);
}

auto get_char_array(const bt_ctf_event* event, const bt_definition* scope, const char* name)
{
    return get(event, scope, name, bt_ctf_get_char_array);
}

auto get_string(const bt_ctf_event* event, const bt_definition* scope, const char* name)
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

template<typename List, typename Needle>
bool contains(List&& list, const Needle& needle)
{
    return std::find(list.begin(), list.end(), needle) != list.end();
}

template<typename T1, typename T2>
bool contains(const std::initializer_list<T1>& list, const T2& needle)
{
    return std::find(begin(list), end(list), needle) != end(list);
}

template<typename Whitelist, typename Needle>
bool isWhitelisted(const Whitelist& whitelist, const Needle& needle)
{
    return whitelist.empty() || contains(whitelist, needle);
}

template<typename T>
auto findMmapAt(T&& mmaps, uint64_t addr)
{
    for (auto it = mmaps.begin(), end = mmaps.end(); it != end; ++it) {
        if (it->addr > addr)
            break;
        if (it->addr <= addr && addr < (it->addr + it->len))
            return it;
    }
    return mmaps.end();
}

struct KMemAlloc
{
    uint64_t requested = 0;
    uint64_t allocated = 0;
};

KMemAlloc operator+(const KMemAlloc& lhs, const KMemAlloc& rhs)
{
    return {lhs.requested + rhs.requested, lhs.allocated + rhs.allocated};
}

KMemAlloc operator-(const KMemAlloc& lhs, const KMemAlloc& rhs)
{
    return {lhs.requested - rhs.requested, lhs.allocated - rhs.allocated};
}

KMemAlloc& operator+=(KMemAlloc& lhs, const KMemAlloc& rhs)
{
    lhs = lhs + rhs;
    return lhs;
}

KMemAlloc& operator-=(KMemAlloc& lhs, const KMemAlloc& rhs)
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
        cores.reserve(32);
        pids.reserve(1024);
        tids.reserve(1024);
        irqs.reserve(32);
        blockDevices.reserve(32);
    }

    double toMs(int64_t timestamp)
    {
        if (options.relativeTimestamps) {
            if (isFilteredByTime(timestamp)) {
                timestamp = 0;
            } else if (!firstTimestamp) {
                firstTimestamp = timestamp;
                timestamp = 0;
            } else {
                timestamp -= firstTimestamp;
            }
        }

        const auto ms = timestamp / 1000;
        const auto ns = timestamp % 1000;
        return static_cast<double>(ms) + static_cast<double>(ns) * 1E-3;
    }

    int64_t tid(uint64_t cpuId) const
    {
        if (cores.size() <= cpuId)
            return INVALID_TID;
        return cores[cpuId].tid;
    }

    int64_t pid(int64_t tid) const
    {
        auto it = tids.find(tid);
        return it == tids.end() ? INVALID_TID : it->second.pid;
    }

    void setTid(uint64_t cpuId, int64_t tid)
    {
        if (cores.size() <= cpuId)
            cores.resize(cpuId + 1);
        cores[cpuId].tid = tid;
    }

    void setPid(int64_t tid, int64_t pid)
    {
        tids[tid].pid = pid;
    }

    void setOpenAtFilename(int64_t tid, std::string_view filename)
    {
        tids[tid].openAtFilename = filename;
    }

    void setOpenAtFd(int64_t pid, int64_t tid, int64_t fd)
    {
        pids[pid].fdToFilename[fd] = std::move(tids[tid].openAtFilename);
    }

    void setFdFilename(int64_t pid, int64_t fd, std::string_view filename)
    {
        pids[pid].fdToFilename[fd] = filename;
    }

    void closeFd(int64_t pid, int64_t fd)
    {
        auto& fds = pids[pid].fdToFilename;
        auto it = fds.find(fd);
        if (it != fds.end())
            fds.erase(it);
    }

    std::string_view fdToFilename(int64_t pid, int64_t fd) const
    {
        auto pid_it = pids.find(pid);
        if (pid_it == pids.end())
            return "??";
        const auto& fds = pid_it->second.fdToFilename;
        auto fd_it = fds.find(fd);
        if (fd_it == fds.end())
            return "??";
        return fd_it->second;
    }

    void setIrqName(uint64_t irq, std::string_view name, std::string_view action)
    {
        irqs[irq] = {std::string(name), std::string(action)};
    }

    struct IrqDataView
    {
        std::string_view name;
        std::string_view action;
    };
    IrqDataView irq(uint64_t irq) const
    {
        auto it = irqs.find(irq);
        if (it == irqs.end())
            return {};
        return {it->second.name, it->second.action};
    }

    void setBlockDeviceName(uint64_t device, std::string_view name)
    {
        blockDevices[device] = name;
    }

    std::string_view blockDeviceName(uint64_t device) const
    {
        auto it = blockDevices.find(device);
        if (it == blockDevices.end())
            return "??";
        return it->second;
    }

    void mmap(int64_t pid, uint64_t addr, uint64_t len, std::string_view file, int64_t fd)
    {
        auto& mmaps = pids[pid].mmaps;
        auto it =
            std::lower_bound(mmaps.begin(), mmaps.end(), addr, [](auto map, auto addr) { return map.addr < addr; });
        mmaps.insert(it, {addr, len, std::string(file), fd});
    }

    void mmapEntry(int64_t tid, uint64_t len, int64_t fd)
    {
        tids[tid].mmapEntry = {len, fd};
    }

    void mmapExit(int64_t pid, int64_t tid, uint64_t addr, int64_t timestamp)
    {
        auto& entry = tids[tid].mmapEntry;
        if (addr && entry.len) {
            mmap(pid, addr, entry.len, fdToFilename(pid, entry.fd), entry.fd);
            anonMmapped(pid, timestamp, entry.fd, entry.len, true);
        }
        entry = {};
    }

    void munmap(int64_t pid, uint64_t addr, uint64_t len, int64_t timestamp)
    {
        auto& mmaps = pids[pid].mmaps;
        auto it = findMmapAt(mmaps, addr);
        if (it == mmaps.end())
            return;

        anonMmapped(pid, timestamp, it->fd, len, false);

        if (it->addr == addr && it->len == len) {
            mmaps.erase(it);
            return;
        } else if (it->addr == addr) {
            it->addr += len;
        } else if (it->addr + len == addr + len) {
            it->len -= len;
        } else {
            // split up
            const auto trailing = it->addr + it->len - addr - len;
            it->len = (addr - it->addr);
            mmaps.insert(it + 1, {addr + len, trailing, it->file, it->fd});
        }
    }

    std::string_view fileMmappedAt(int64_t pid, uint64_t addr) const
    {
        auto pid_it = pids.find(pid);
        if (pid_it == pids.end())
            return "??";

        const auto& mmaps = pid_it->second.mmaps;
        auto it = findMmapAt(mmaps, addr);
        if (it == mmaps.end())
            return "??";
        return it->file;
    }

    void fork(int64_t parentPid, int64_t childPid)
    {
        // follow children by default
        if (options.processWhitelist.empty())
            return;
        if (!contains(options.pidWhitelist, parentPid) || contains(options.pidWhitelist, childPid))
            return;
        options.pidWhitelist.push_back(childPid);
    }

    void threadExit(int64_t tid, int64_t pid, int64_t timestamp)
    {
        if (tid == pid) {
            auto pid_it = pids.find(pid);
            if (pid_it != pids.end()) {
                if (pid_it->second.anonMmapped > 0) {
                    // reset counters to zero to ensure the graph expands the full width of process lifetime
                    printEvent(
                        R"({"name": "anon mmapped", "ph": "C", "ts": %.*g, "pid": %ld, "tid": %ld, "args": {"value": 0}})",
                        TIMESTAMP_PRECISION, toMs(timestamp), pid, pid);
                }
                pids.erase(pid_it);
            }
        }

        if (auto tid_it = tids.find(tid); tid_it != tids.end())
            tids.erase(tids.find(tid));
    }

    void printName(int64_t tid, int64_t pid, std::string_view name, int64_t timestamp)
    {
        if (tid == pid) {
            bool whiteListedPid = contains(options.pidWhitelist, pid);
            if (isFilteredByProcessName(name) && !whiteListedPid)
                return;

            if (!options.processWhitelist.empty() && !whiteListedPid)
                options.pidWhitelist.push_back(pid); // add pid to filer to exclude events
        }

        if (isFilteredByPid(pid))
            return;

        auto getName = [this](int64_t id) -> std::string& {
            auto it = tids.find(id);
            if (it == tids.end())
                it = tids.insert(it, {id, {}});
            return it->second.name;
        };

        auto printName = [this, tid, pid, name, timestamp](const char* type) {
            printEvent(R"({"name": "%s", "ph": "M", "ts": %.*g, "pid": %ld, "tid": %ld, "args": {"name": "%.*s"}})",
                       type, TIMESTAMP_PRECISION, toMs(timestamp), pid, tid, name.size(), name.data());
        };

        if (pid != INVALID_TID) {
            auto& pidName = getName(pid);
            if (pidName.empty() || (tid == pid && pidName != name)) {
                pidName = name;
                printName("process_name");
                if (tid == pid) {
                    // always update main thread name when we update the process name
                    printName("thread_name");
                    return;
                }
            }
        }
        if (tid != INVALID_TID) {
            auto& tidName = getName(tid);
            if (tidName != name) {
                tidName = name;
                printName("thread_name");
            }
        }
    }

    template<typename... T>
    void printEvent(const char* fmt, T... args)
    {
        if (!firstEvent)
            printf(",");
        firstEvent = false;

        printf("\n    ");

        printf(fmt, args...);
    }

    void parseEvent(bt_ctf_event* event);

    enum KMemType
    {
        KMalloc,
        CacheAlloc,
    };
    void alloc(uint64_t ptr, const KMemAlloc& alloc, int64_t timestamp, KMemType type)
    {
        auto& hash = type == KMalloc ? kmem : kmemCached;
        auto& current = type == KMalloc ? currentAlloc : currentCached;
        hash[ptr] = alloc;
        current += alloc;
        printCount(type, timestamp);
    }

    void free(uint64_t ptr, int64_t timestamp, KMemType type)
    {
        auto& hash = type == KMalloc ? kmem : kmemCached;
        auto& current = type == KMalloc ? currentAlloc : currentCached;
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
        if (prevTid == nextTid || isFilteredByTime(timestamp))
            return;

        if (cores.size() <= cpuId)
            cores.resize(cpuId);

        auto& core = cores[cpuId];

        const bool wasRunning = core.running;
        const bool isRunning = nextTid != SWAPPER_TID;
        if (wasRunning != isRunning) {
            const auto numRunning = std::count_if(cores.begin(), cores.end(), [](auto core) { return core.running; });
            printCount(CounterGroup::CPU, "CPU utilization", numRunning, timestamp);
            core.running = isRunning;
        }

        const auto group = dataFor(CounterGroup::CPU);
        const auto eventTid = CPU_PROCESS_TID_MULTIPLICATOR * static_cast<int64_t>(cpuId + 1);
        if (!core.printedCpuStateName) {
            printEvent(
                R"({"name": "thread_name", "ph": "M", "pid": %ld, "tid": %ld, "args": { "name": "CPU %lu State" }})",
                group.id, eventTid, cpuId);
            core.printedCpuStateName = true;
        }

        auto printCpuCoreProcessEvent = [this, eventTid, timestamp, group](int64_t tid, char type) {
            if (tid == SWAPPER_TID)
                return;

            if (isFilteredByPid(pid(tid)))
                return;

            const auto& comm = tids[tid].name;
            printEvent(R"#({"name": "%s (%ld)", "ph": "%c", "ts": %.*g, "pid": %ld, "tid": %ld, "cat": "process"})#",
                       comm.c_str(), tid, type, TIMESTAMP_PRECISION, toMs(timestamp), group.id, eventTid);
        };
        printCpuCoreProcessEvent(prevTid, 'E');
        printCpuCoreProcessEvent(nextTid, 'B');
    }

    void cpuFrequency(uint64_t cpuId, uint64_t frequency, int64_t timestamp)
    {
        printCount(CounterGroup::CPU, "CPU " + std::to_string(cpuId) + " frequency", frequency, timestamp);
    }

    bool isFiltered(std::string_view name) const
    {
        return std::any_of(options.exclude.begin(), options.exclude.end(),
                           [name](const auto& pattern) { return name.find(pattern) != name.npos; });
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

    bool isFilteredByTime(int64_t timestamp) const
    {
        if (options.minTime && timestamp < options.minTime)
            return true;
        if (options.maxTime && timestamp > options.maxTime)
            return true;
        return false;
    }

    void printStats(std::ostream& out) const
    {
        if (!options.enableStatistics)
            return;

        out << "Trace Data Statistics:\n\n";

        auto printSortedStats = [&out](const auto& stats) {
            auto sortedStats = stats;
            std::sort(sortedStats.begin(), sortedStats.end(),
                      [](const auto& lhs, const auto& rhs) { return lhs.counter < rhs.counter; });
            for (const auto& entry : sortedStats)
                out << std::setw(16) << entry.counter << '\t' << entry.name << '\n';
        };

        out << "Event Stats:\n";
        printSortedStats(eventStats);

        out << "\nEvent Category Stats:\n";
        printSortedStats(categoryStats);
    }

private:
    void anonMmapped(int64_t pid, int64_t timestamp, int64_t fd, uint64_t len, bool add)
    {
        if (fd != -1 || isFilteredByPid(pid) || isFilteredByTime(timestamp))
            return;

        auto& anonMmapped = pids[pid].anonMmapped;
        if (add)
            anonMmapped += len;
        else
            anonMmapped -= len;

        printEvent(R"({"name": "anon mmapped", "ph": "C", "ts": %.*g, "pid": %ld, "tid": %ld, "args": {"value": %ld}})",
                   TIMESTAMP_PRECISION, toMs(timestamp), pid, pid, anonMmapped);
    }
    void count(std::string_view name, std::string_view category)
    {
        if (!options.enableStatistics)
            return;

        auto count = [](auto& stats, auto name) {
            auto it = std::lower_bound(stats.begin(), stats.end(), name,
                                       [](const auto& entry, const auto& name) { return entry.name < name; });
            if (it == stats.end() || it->name != name)
                it = stats.insert(it, {std::string(name)});
            it->counter++;
        };
        count(eventStats, name);
        count(categoryStats, category.empty() ? "uncategorized" : category);
    }

    void printCount(KMemType type, int64_t timestamp)
    {
        const auto& current = type == KMalloc ? currentAlloc : currentCached;
        printCount(CounterGroup::Memory, type == KMalloc ? "kmem_kmalloc_requested" : "kmem_cache_alloc_requested",
                   current.requested, timestamp);
        printCount(CounterGroup::Memory, type == KMalloc ? "kmem_kmalloc_allocated" : "kmem_cache_alloc_allocated",
                   current.allocated, timestamp);
    }

    enum SpecialIds
    {
        INVALID_TID = -1,
        CPU_COUNTER_PID = -2,
        MEMORY_COUNTER_PID = -3,
        // cpu id * multiplicator gives us a thread id for per-core events
        CPU_PROCESS_TID_MULTIPLICATOR = -100,
    };
    enum class CounterGroup
    {
        CPU,
        Memory,
    };
    struct GroupData
    {
        const char* const name;
        const int64_t id;
        bool namePrinted;
    };
    GroupData dataFor(CounterGroup counterGroup)
    {
        static GroupData groups[] = {
            {"CPU statistics", CPU_COUNTER_PID, false},
            {"Memory statistics", MEMORY_COUNTER_PID, false},
        };
        const auto groupIndex = static_cast<std::underlying_type_t<CounterGroup>>(counterGroup);
        auto& group = groups[groupIndex];
        if (!group.namePrinted) {
            printEvent(
                R"({"name": "process_sort_index", "ph": "M", "pid": %1$ld, "tid": %1$ld, "args": { "sort_index": %1$ld }})",
                group.id);
            printEvent(R"({"name": "process_name", "ph": "M", "pid": %1$ld, "tid": %1$ld, "args": { "name": "%2$s" }})",
                       group.id, group.name);
            group.namePrinted = true;
        }
        return group;
    }
    void printCount(CounterGroup counterGroup, std::string_view name, int64_t value, int64_t timestamp)
    {
        if (isFiltered(name) || isFilteredByTime(timestamp))
            return;

        const auto group = dataFor(counterGroup);
        count(name, group.name);

        printEvent(R"({"name": "%.*s", "ph": "C", "ts": %.*g, "pid": %ld, "tid": %ld, "args": {"value": %ld}})",
                   name.size(), name.data(), TIMESTAMP_PRECISION, toMs(timestamp), group.id, group.id, value);
    }

    struct CoreData
    {
        // currently running thread id
        int64_t tid = INVALID_TID;
        // true if core is currently running a non-idle process
        bool running = false;
        // true if we printed the name for the 'CPU State' thread
        bool printedCpuStateName = false;
    };
    std::vector<CoreData> cores;
    struct TidData
    {
        int64_t pid = INVALID_TID;
        std::string name;
        std::string openAtFilename;
        struct MMapEntry
        {
            uint64_t len = 0;
            int64_t fd = -1;
        };
        MMapEntry mmapEntry;
    };
    std::unordered_map<int64_t, TidData> tids;
    struct MMap
    {
        uint64_t addr = 0;
        uint64_t len = 0;
        std::string file;
        int64_t fd = -1;
    };
    struct PidData
    {
        std::unordered_map<int64_t, std::string> fdToFilename;
        std::vector<MMap> mmaps;
        uint64_t anonMmapped = 0;
    };
    std::unordered_map<int64_t, PidData> pids;
    struct IrqData
    {
        std::string name;
        std::string action;
    };
    std::unordered_map<uint64_t, IrqData> irqs;
    std::unordered_map<uint64_t, std::string> blockDevices;
    std::unordered_map<uint64_t, KMemAlloc> kmem;
    std::unordered_map<uint64_t, KMemAlloc> kmemCached;
    KMemAlloc currentAlloc;
    KMemAlloc currentCached;
    std::unordered_map<uint64_t, uint64_t> kmemPages;
    uint64_t currentKmemPages = 0;
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
    std::stringstream argsStream;
    int64_t firstTimestamp = 0;
};

struct Event
{
    Event(bt_ctf_event* event, Context* context)
        : ctf_event(event)
        , event_fields_scope(bt_ctf_get_top_level_scope(event, BT_EVENT_FIELDS))
        , name(bt_ctf_event_name(event))
        , timestamp(bt_ctf_get_timestamp(event))
        , isFilteredByTime(context->isFilteredByTime(timestamp))
    {
        auto stream_packet_context_scope = bt_ctf_get_top_level_scope(event, BT_STREAM_PACKET_CONTEXT);
        if (!stream_packet_context_scope)
            fprintf(stderr, "failed to get stream packet context scope\n");

        cpuId = get_uint64(event, stream_packet_context_scope, "cpu_id").value();

        tid = context->tid(cpuId);
        pid = context->pid(tid);

        if (!event_fields_scope) {
            fprintf(stderr, "failed to get event fields scope\n");
            return;
        }

        if (name == "sched_switch") {
            const auto next_tid = get_int64(event, event_fields_scope, "next_tid").value();
            context->setTid(cpuId, next_tid);

            const auto next_pid = context->pid(next_tid);
            const auto next_comm = get_char_array(event, event_fields_scope, "next_comm").value();
            context->printName(next_tid, next_pid, next_comm, timestamp);

            const auto prev_tid = get_int64(event, event_fields_scope, "prev_tid").value();
            const auto prev_pid = context->pid(prev_tid);
            const auto prev_comm = get_char_array(event, event_fields_scope, "prev_comm").value();
            context->printName(prev_tid, prev_pid, prev_comm, timestamp);

            context->schedSwitch(cpuId, prev_tid, next_tid, timestamp);

            // TODO: look into flow events?
            if (!context->isFilteredByPid(prev_pid) && !isFilteredByTime) {
                context->printEvent(
                    R"({"name": "sched_switch", "ph": "B", "ts" : %.*g, "pid": %ld, "tid": %ld, "cat": "sched", "args": {"out": {"next_comm": "%s", "next_pid": %ld, "next_tid": %ld}}})",
                    TIMESTAMP_PRECISION, context->toMs(timestamp), prev_pid, prev_tid, next_comm, next_pid, next_tid);
            }
            if (!context->isFilteredByPid(next_pid) && !isFilteredByTime) {
                context->printEvent(
                    R"({"name": "sched_switch", "ph": "E", "ts" : %.*g, "pid": %ld, "tid": %ld, "cat": "sched", "args": {"in": {"prev_comm": "%s", "prev_pid": %ld, "prev_tid": %ld}}})",
                    TIMESTAMP_PRECISION, context->toMs(timestamp), next_pid, next_tid, prev_comm, prev_pid, prev_tid);
            }
        } else if (name == "sched_process_fork") {
            const auto parent_pid = get_int64(event, event_fields_scope, "parent_pid").value();
            const auto child_tid = get_int64(event, event_fields_scope, "child_tid").value();
            const auto child_pid = get_int64(event, event_fields_scope, "child_pid").value();
            context->setPid(child_tid, child_pid);

            const auto child_comm = get_char_array(event, event_fields_scope, "child_comm").value();
            context->printName(child_tid, child_pid, child_comm, timestamp);
            context->fork(parent_pid, child_pid);
        } else if (name == "sched_process_free") {
            const auto tid = get_int64(event, event_fields_scope, "tid").value();
            const auto pid = context->pid(tid);
            context->threadExit(tid, pid, timestamp);
        } else if (name == "sched_process_exec") {
            const auto tid = get_int64(event, event_fields_scope, "tid").value();
            const auto pid = context->pid(tid);
            context->setPid(tid, pid);

            auto filename = std::string_view(get_string(event, event_fields_scope, "filename").value());
            auto it = filename.find_last_of('/');
            if (it != filename.npos)
                filename.remove_prefix(it + 1);
            context->printName(tid, pid, filename, timestamp);
        } else if (name == "lttng_statedump_process_state") {
            const auto cpu = get_uint64(event, event_fields_scope, "cpu").value();
            const auto vtid = get_int64(event, event_fields_scope, "vtid").value();
            const auto vpid = get_int64(event, event_fields_scope, "vpid").value();

            context->setTid(cpu, vtid);
            context->setPid(vtid, vpid);

            const auto name = get_char_array(event, event_fields_scope, "name").value();
            context->printName(vtid, vpid, name, timestamp);
        } else if (name == "lttng_statedump_interrupt") {
            const auto irq = get_uint64(event, event_fields_scope, "irq").value();
            const auto name = get_string(event, event_fields_scope, "name").value();
            const auto action = get_string(event, event_fields_scope, "action").value();
            context->setIrqName(irq, name, action);
        } else if (name == "lttng_statedump_block_device") {
            const auto device = get_uint64(event, event_fields_scope, "dev").value();
            const auto diskname = get_string(event, event_fields_scope, "diskname").value();
            context->setBlockDeviceName(device, diskname);
        } else if (name == "lttng_statedump_file_descriptor") {
            const auto pid = get_int64(event, event_fields_scope, "pid").value();
            const auto fd = get_int64(event, event_fields_scope, "fd").value();
            const auto filename = get_string(event, event_fields_scope, "filename").value();
            context->setFdFilename(pid, fd, filename);
        } else if (name == "lttng_ust_statedump:bin_info") {
            const auto baddr = get_uint64(event, event_fields_scope, "baddr").value();
            const auto memsz = get_uint64(event, event_fields_scope, "memsz").value();
            const auto path = get_string(event, event_fields_scope, "path").value();
            context->mmap(pid, baddr, memsz, path, -1);
        } else if (name == "syscall_entry_mmap") {
            const auto len = get_uint64(event, event_fields_scope, "len").value();
            const auto fd = get_int64(event, event_fields_scope, "fd").value();
            context->mmapEntry(tid, len, fd);
        } else if (name == "syscall_exit_mmap") {
            const auto ret = get_uint64(event, event_fields_scope, "ret").value();
            context->mmapExit(pid, tid, ret, timestamp);
        } else if (name == "syscall_entry_munmap") {
            const auto addr = get_uint64(event, event_fields_scope, "addr").value();
            const auto len = get_uint64(event, event_fields_scope, "len").value();
            context->munmap(pid, addr, len, timestamp);
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

        auto removeSuffix = [this](std::string_view suffix) {
            if (!endsWith(name, suffix))
                return false;
            name.remove_suffix(suffix.length());
            return true;
        };

        auto rewriteName = [this](std::string_view needle, std::string_view replacement, bool atStart) {
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

        if (removeSuffix("_entry") || rewriteName("syscall_entry_", "syscall_", true)
            || rewriteName("_begin_", "_", false) || rewriteName("_before_", "_", false))
            type = 'B';
        else if (removeSuffix("_exit") || rewriteName("syscall_exit_", "syscall_", true)
                 || rewriteName("_end_", "_", false) || rewriteName("_after_", "_", false))
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

    const bt_ctf_event* ctf_event = nullptr;
    const bt_definition* event_fields_scope = nullptr;
    std::string_view name;
    // when we rewrite the name, this is the source for the string_view
    std::string mutatedName;
    std::string_view category;
    int64_t timestamp = 0;
    uint64_t cpuId = 0;
    int64_t tid = -1;
    int64_t pid = -1;
    char type = 'i';
    bool isFilteredByTime = false;
};

enum class ArgError
{
    UnknownType,
    UnknownSignedness,
    UnhandledArrayType,
    UnhandledType,
};

template<typename ValueFormatter>
void addArg(const bt_ctf_event* event, const bt_declaration* decl, const bt_definition* def, ValueFormatter&& formatter)
{
    const auto type = bt_ctf_field_type(decl);
    const auto field_name = bt_ctf_field_name(def);

    // skip sequence lengths
    if (type == CTF_TYPE_INTEGER && startsWith(field_name, "_") && endsWith(field_name, "_length"))
        return;

    switch (type) {
    case CTF_TYPE_UNKNOWN:
        formatter(field_name, ArgError::UnknownType);
        break;
    case CTF_TYPE_INTEGER:
        switch (bt_ctf_get_int_signedness(decl)) {
        case 0:
            formatter(field_name, bt_ctf_get_uint64(def));
            break;
        case 1:
            formatter(field_name, bt_ctf_get_int64(def));
            break;
        default:
            formatter(field_name, ArgError::UnknownSignedness);
            break;
        }
        break;
    case CTF_TYPE_STRING:
        formatter(field_name, bt_ctf_get_string(def));
        break;
    case CTF_TYPE_ARRAY: {
        const auto encoding = bt_ctf_get_encoding(decl);
        if (encoding == CTF_STRING_ASCII || encoding == CTF_STRING_UTF8) {
            formatter(field_name, bt_ctf_get_char_array(def));
            break;
        }
        [[fallthrough]];
    }
    case CTF_TYPE_VARIANT:
    case CTF_TYPE_STRUCT:
    case CTF_TYPE_SEQUENCE: {
        unsigned int numEntries = 0;
        const bt_definition* const* sequence = nullptr;
        if (bt_ctf_get_field_list(event, def, &sequence, &numEntries) != 0 || numEntries == 0) {
            // empty sequence, skip
            return;
        }
        formatter(field_name, sequence, numEntries, type);
        break;
    }
    default:
        formatter(field_name, ArgError::UnhandledType, type);
        break;
    }
}

template<typename ValueFormatter>
void fillArgs(const bt_ctf_event* event, const bt_definition* scope, ValueFormatter&& formatter)
{
    unsigned int fields = 0;
    const bt_definition* const* list = nullptr;
    if (bt_ctf_get_field_list(event, scope, &list, &fields) != 0) {
        fprintf(stderr, "failed to read field list\n");
        return;
    }
    for (unsigned int i = 0; i < fields; ++i) {
        auto def = list[i];
        auto decl = bt_ctf_get_decl_from_def(def);
        if (!decl) {
            fprintf(stderr, "invalid declaration for field %u\n", i);
            continue;
        }
        addArg(event, decl, def, formatter);
    }
}

struct Formatter
{
    Formatter(std::stringstream& stream, Context* context, const Event* event)
        : stream(stream)
        , context(context)
        , event(event)
    {
    }

    void operator()(std::string_view field, int64_t value)
    {
#if Qt5Gui_FOUND
        if (startsWith(event->category, "qt")) {
            auto isEventType = [this, field]() {
                if (field != "type")
                    return false;
                if (event->name.find("Event") != event->name.npos)
                    return true;
                if (event->name.find("Application_notify") != event->name.npos)
                    return true;
                return false;
            };
            if (isEventType()) {
                const auto metaEnum = QMetaEnum::fromType<QEvent::Type>();
                const auto values = metaEnum.valueToKeys(value);
                if (!values.isEmpty()) {
                    (*this)(field, values.constData());
                    return;
                }
            }
        }
#endif
        newField(field);
        stream << std::to_string(value);

        if (event->category == "syscall") {
            if (field == "fd" && value != -1) {
                (*this)("file", context->fdToFilename(event->pid, value));
            } else if (field == "ret") {
                if (event->name == "syscall_openat")
                    context->setOpenAtFd(event->pid, event->tid, value);
                else if (event->name == "syscall_socket")
                    context->setFdFilename(event->pid, value, "socket");
                else if (event->name == "syscall_eventfd2")
                    context->setFdFilename(event->pid, value, "eventfd");
            }
        }
    }

    bool isHexField(std::string_view field) const
    {
        if (event->category == "kmem") {
            if (contains({"call_site", "ptr", "page"}, field))
                return true;
        } else if (event->category == "syscall") {
            if (contains({"addr", "buf", "start"}, field))
                return true;

            if (event->name == "syscall_rt_sigprocmask" && contains({"nset", "oset"}, field))
                return true;

            if (event->name == "syscall_futex" && contains({"uaddr", "uaddr2"}, field))
                return true;

            if (event->name == "syscall_mmap" && field == "ret")
                return true;

            if (field == "msg" && (event->name == "syscall_sendmsg" || event->name == "syscall_recvmsg"))
                return true;

            if (event->name == "syscall_ppoll" && field == "tsp")
                return true;

            if (endsWith(event->name, "stat") && field == "statbuf")
                return true;
        } else if (startsWith(event->category, "qt")) {
            if (contains({"object", "event", "sender", "receiver", "slotObject"}, field))
                return true;

            if (event->name == "qtgui:QImageReader_read_reading" && field == "reader")
                return true;
        } else if (event->category == "x86_exceptions_page_fault" && contains({"address", "ip"}, field)) {
            return true;
        } else if (event->category == "lttng_ust_statedump" && field == "baddr") {
            return true;
        }

        return false;
    }

    void operator()(std::string_view field, uint64_t value)
    {
        newField(field);

        if (isHexField(field)) {
            stream << "\"0x" << std::hex << value << '"' << std::dec;
        } else {
            stream << value;
        }

        if (inArray && parentField == "fildes" && event->name == "syscall_pipe2") {
            context->setFdFilename(event->pid, value, index == 0 ? "pipe(read)" : "pipe(write)");
        } else if (field == "fd" && event->category == "syscall") {
            (*this)("file", context->fdToFilename(event->pid, static_cast<int64_t>(value)));
            if (event->name == "syscall_close")
                context->closeFd(event->pid, value);
        } else if (event->category == "irq" && field == "vec") {
            const auto& irq = context->irq(value);
            (*this)("name", irq.name);
            (*this)("action", irq.action);
        } else if (event->category == "block") {
            if (field == "dev")
                (*this)("dev_name", context->blockDeviceName(value));
            else if (field == "old_dev")
                (*this)("old_dev_name", context->blockDeviceName(value));
        } else if (event->category == "x86_exceptions_page_fault" && field == "address") {
            (*this)("file", context->fileMmappedAt(event->pid, value));
        }
    }

    void operator()(std::string_view field, std::string_view value)
    {
        newField(field);
        writeString(value);
        if (event->name == "syscall_openat" && field == "filename") {
            context->setOpenAtFilename(event->tid, value);
        }
    }

    void operator()(std::string_view field, ArgError error, int64_t arg = 0)
    {
        newField(field);
        switch (error) {
        case ArgError::UnknownType:
            stream << "\"<unknown type>\"";
            break;
        case ArgError::UnknownSignedness:
            stream << "\"<unknown signedness>\"";
            break;
        case ArgError::UnhandledArrayType:
            stream << "\"<unhandled array type " << arg << ">\"";
            break;
        case ArgError::UnhandledType:
            stream << "\"<unhandled type " << arg << ">\"";
            break;
        }
    }

    void operator()(std::string_view field, const bt_definition* const* sequence, unsigned numEntries, ctf_type_id type)
    {
        if (type == CTF_TYPE_SEQUENCE && startsWith(event->category, "qt")) {
            std::string string;
            for (unsigned i = 0; i < numEntries; ++i) {
                const auto* def = sequence[i];
                const auto* decl = bt_ctf_get_decl_from_def(def);
                const auto type = bt_ctf_field_type(decl);
                if (type != CTF_TYPE_INTEGER) {
                    std::cerr << "unexpected sequence type for qt tracepoint " << field << ": " << type << std::endl;
                    break;
                }
                const auto signedness = bt_ctf_get_int_signedness(decl);
                if (signedness != 0) {
                    std::cerr << "unexpected sequence signedness for qt tracepoint " << field << ": " << signedness
                              << std::endl;
                    break;
                }
                // TODO: convert utf16 to utf8
                string.push_back(static_cast<char>(bt_ctf_get_uint64(def)));
            }
            (*this)(field, string);
            return;
        }

        const auto isArray = type == CTF_TYPE_SEQUENCE || type == CTF_TYPE_ARRAY;

        newField(field);
        stream << (isArray ? '[' : '{');

        Formatter childFormatter(stream, context, event);
        childFormatter.inArray = isArray;
        childFormatter.parentField = field;
        for (unsigned i = 0; i < numEntries; ++i) {
            childFormatter.index = i;
            const auto* def = sequence[i];
            const auto* decl = bt_ctf_get_decl_from_def(def);
            addArg(event->ctf_event, decl, def, childFormatter);
        }

        stream << (isArray ? ']' : '}');
    }

    void newField(std::string_view field)
    {
        if (firstField)
            firstField = false;
        else
            stream << ", ";

        if (inArray)
            return;

        writeString(field);
        stream << ": ";
    }

    void writeString(std::string_view string)
    {
        stream << '"';
        for (auto c : string) {
            if (c == '\\')
                stream << "\\\\";
            else if (c == '"')
                stream << "\\\"";
            else
                stream << c;
        }
        stream << '"';
    }

    std::stringstream& stream;
    Context* context;
    const Event* event;
    bool firstField = true;
    bool inArray = false;
    unsigned index = 0;
    std::string_view parentField;
};

void Context::parseEvent(bt_ctf_event* ctf_event)
{
    const auto event = Event(ctf_event, this);

    count(event.name, event.category);

    if (event.isFilteredByTime || isFiltered(event.name) || isFilteredByPid(event.pid))
        return;

    argsStream.str({});
    if (event.event_fields_scope)
        fillArgs(ctf_event, event.event_fields_scope, Formatter(argsStream, this, &event));

    if (event.category.empty()) {
        printEvent(R"({"name": "%.*s", "ph": "%c", "ts": %.*g, "pid": %ld, "tid": %ld, "args": {%s}})",
                   event.name.size(), event.name.data(), event.type, TIMESTAMP_PRECISION, toMs(event.timestamp),
                   event.pid, event.tid, argsStream.str().c_str());
    } else {
        printEvent(R"({"name": "%.*s", "ph": "%c", "ts": %.*g, "pid": %ld, "tid": %ld, "cat": "%.*s", "args": {%s}})",
                   event.name.size(), event.name.data(), event.type, TIMESTAMP_PRECISION, toMs(event.timestamp),
                   event.pid, event.tid, event.category.size(), event.category.data(), argsStream.str().c_str());
    }
}

int main(int argc, char** argv)
{
    Context context(parseCliOptions(argc, argv));

    auto ctx = wrap(bt_context_create(), bt_context_put);

    bool hasTrace = false;
    findMetadataFiles(context.options.path, [&ctx, &hasTrace](const char* path) {
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

    printf("{\n  \"traceEvents\": [");

    do {
        auto ctf_event = bt_ctf_iter_read_event(iter.get());
        if (!ctf_event)
            break;

        try {
            context.parseEvent(ctf_event);
        } catch (const std::exception& exception) {
            fprintf(stderr, "Failed to parse event: %s\n", exception.what());
        }
    } while (bt_iter_next(bt_ctf_get_iter(iter.get())) == 0);

    printf("\n  ]\n}\n");

    context.printStats(std::cerr);

    return 0;
}
