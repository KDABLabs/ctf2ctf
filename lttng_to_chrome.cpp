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
#include <cstdio>

template<typename T, typename Cleanup>
auto wrap(T* value, Cleanup cleanup)
{
    return std::unique_ptr<T, Cleanup>(value, cleanup);
}

void convert(bt_ctf_event *event)
{
    const auto name = bt_ctf_event_name(event);
    const auto timestamp = bt_ctf_get_timestamp(event);
    printf("{\"name\": \"%s\", \"ts\": %lu}", name, timestamp);
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

    bool firstEvent = true;
    do {
        auto ctf_event = bt_ctf_iter_read_event(iter.get());
        if (!ctf_event)
            break;

        if (!firstEvent)
            printf(",");
        printf("\n    ");

        convert(ctf_event);
        firstEvent = false;

    } while (bt_iter_next(bt_ctf_get_iter(iter.get())) == 0);

    printf("\n  ]\n}\n");

    return 0;
}
