#ifndef _dep_h_
#define _dep_h_

#include <vector>
#include <unordered_map>
#include <map>
#include <string>
#include <algorithm>
#include <thread>
#include <atomic>

#include <unistd.h>
#include <cassert>
#include <cmath>

#include <yaml-cpp/yaml.h>
#include <boost/algorithm/string.hpp>

#include "src/logging.hpp"
class dummy_class {
public:
    dummy_class() {
#ifdef LOG_LEVEL_AS_DEBUG
        Log::set_level(Log::DEBUG);
#else
        Log::set_level(Log::INFO);
#endif
    }
};
static dummy_class dummy___;

#include "src/utils.hpp"

#endif
