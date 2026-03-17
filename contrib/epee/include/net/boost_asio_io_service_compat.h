// Compatibility for Boost 1.70+: io_service was renamed to io_context;
// io_context::work is replaced by executor_work_guard.
#pragma once
#include <boost/asio/io_context.hpp>
#include <boost/asio/executor_work_guard.hpp>
namespace boost { namespace asio {
  using io_service = io_context;
  using io_service_work = executor_work_guard<io_context::executor_type>;
} }
