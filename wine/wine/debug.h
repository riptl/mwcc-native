#pragma once

#define TRACE(...) ((void)0)
#define TRACE_(x) TRACE
#define TRACE_ON(x) 0
#define WARN(...) ((void)0)
#define WARN_(x) WARN
#define WARN_ON(x) 0
#define ERR(...) ((void)0)
#define ERR_(x) ERR
#define FIXME(...) ((void)0)

#define WINE_DEFAULT_DEBUG_CHANNEL(x)
#define WINE_DECLARE_DEBUG_CHANNEL(x)
