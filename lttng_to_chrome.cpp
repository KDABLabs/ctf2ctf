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

struct Context
{
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

    void setPid(int64_t tid, int64_t pid)
    {
        tidToPid[tid] = pid;
    }

private:
    std::vector<int64_t> cpuToTid;
    std::unordered_map<int64_t, int64_t> tidToPid;
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
            context->setPid(child_tid, child_pid);
        } else if (name == "lttng_statedump_process_state") {
            const auto vtid = get_int64(event, event_fields_scope, "vtid").value();
            const auto vpid = get_int64(event, event_fields_scope, "vpid").value();
            context->setPid(vtid, vpid);
        }
    }

    void print() const
    {
        printf("{\"name\": \"%s\", \"ts\": %lu, \"pid\": %ld, \"tid\": %ld}", name.data(), timestamp, pid, tid);
    }

    std::string_view name;
    int64_t timestamp = 0;
    uint64_t cpuId = 0;
    int64_t tid = -1;
    int64_t pid = -1;
};

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
    bool firstEvent = true;
    do {
        auto ctf_event = bt_ctf_iter_read_event(iter.get());
        if (!ctf_event)
            break;

        try {
            Event event(ctf_event, &context);

            if (!firstEvent)
                printf(",");
            printf("\n    ");

            event.print();
            firstEvent = false;
        } catch(const std::exception &exception) {
            fprintf(stderr, "Failed to parse event: %s\n", exception.what());
        }
    } while (bt_iter_next(bt_ctf_get_iter(iter.get())) == 0);

    printf("\n  ]\n}\n");

    return 0;
}
