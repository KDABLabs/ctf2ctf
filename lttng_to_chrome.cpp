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

template<typename T, typename Cleanup>
auto wrap(T* value, Cleanup cleanup)
{
    return std::unique_ptr<T, Cleanup>(value, cleanup);
}

int main(int argc, char **argv)
{
    auto ctx = wrap(bt_context_create(), bt_context_put);
    return 0;
}
