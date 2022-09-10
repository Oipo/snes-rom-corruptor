#include <fstream>
#include <iterator>
#include <lyra/lyra.hpp>
#include <spdlog/spdlog.h>
#include <vector>
#include <map>

using namespace std;

// shamelessly copied from https://stackoverflow.com/a/17050528/1460998
vector<vector<uint64_t>> cartesian_product(const vector<vector<uint64_t>>& v) {
    vector<vector<uint64_t>> s = {{}};
    for (const auto& u : v) {
        vector<vector<uint64_t>> r;
        for (const auto& x : s) {
            for (const auto y : u) {
                r.push_back(x);
                r.back().push_back(y);
            }
        }
        s = std::move(r);
    }
    return s;
}

int main(int argc, const char** argv)
{
    string input_file;
    string output_file;
    string start_address{};
    string end_address{};
    string mode;

    string start_address_dec{};
    string end_address_dec{};

    bool help{};
    uint32_t val_dec{};
    uint64_t distance = 1000;
    string val{};
    vector<string> search{};

    auto cli = lyra::opt(input_file, "input")
                ["-i"]["--input"]("Which rom to corrupt").required()
               | lyra::opt(output_file, "output")
                ["-o"]["--output"]("What filename to output to").required()
               | lyra::opt(start_address, "start")
                ["-s"]["--start"]("Start of address to corrupt in hexadecimal")
               | lyra::opt(end_address, "end")
                ["-e"]["--end"]("End of address to corrupt in hexadecimal")
               | lyra::opt(start_address_dec, "start")
                ["-S"]("Start of address to corrupt in decimal")
               | lyra::opt(end_address_dec, "end")
                ["-E"]("End of address to corrupt in decimal")
               | lyra::opt(val, "value")
                ["-V"]["--value"]("Value in hex to set bytes to in mode 'set'")
               | lyra::opt(val_dec, "value")
                ["-v"]("Value in decimal to set bytes to in mode 'set'")
               | lyra::opt(distance, "distance")
                ["-d"]["--distance"]("Max distance the searched value locations can be apart 'search'")
               | lyra::opt([&](const string &val){ search.push_back(val); }, "search")
                ["--search"]("Search values in hex that follow after each other with other values in between in mode 'search'. Good for finding tables with info.").cardinality(0, 99)
               | lyra::opt(mode, "mode")
                ["-m"]["--mode"]("Which mode to use to corrupt: 'up' to modify bytes up by 1, 'down' to modify bytes down by 1").required();

    cli.add_argument(lyra::help(help));

    auto result = cli.parse({argc, argv});

    if(help) {
        cout << cli;
        return 0;
    }

    if(!result) {
        spdlog::error("Error in command line: {}", result.message());
        return 1;
    }

    if(mode != "up" && mode != "up2" && mode != "down" && mode != "set" && mode != "search") {
        spdlog::error("mode '{}' unsupported. Supported modes: 'up', 'up2', 'down', 'set', 'search'", mode);
        return 1;
    }

    if(mode == "search") {
        if(search.size() < 2) {
            spdlog::error("Search mode needs at least 2 search values");
            return 1;
        }

        uint64_t start{};
        if(!start_address.empty()) {
            stringstream stream;
            stream << start_address;
            stream >> std::hex >> start;
        }
        if(!start_address_dec.empty()) {
            stringstream stream;
            stream << start_address_dec;
            stream >> start;
        }

        {
            std::string out{};
            fmt::format_to(std::back_inserter(out), "searching with offset 0x{:X} for: 0x{}", start, search[0]);
            for (uint64_t i = 1; i < search.size(); i++) {
                fmt::format_to(std::back_inserter(out), ", 0x{}", search[i]);
            }
            spdlog::info(out);
        }

        ifstream input(input_file, ios::binary);

        vector<char> bytes{istreambuf_iterator<char>(input), istreambuf_iterator<char>()};

        map<uint64_t, vector<uint64_t>> locs{};
        vector<uint64_t> search_vals_dec{};
        for(const string &s : search) {
            uint64_t search_val{};
            {
                stringstream stream;
                stream << s;
                stream >> std::hex >> search_val;
            }

            if(search_val > 255) {
                spdlog::error("search val 0x{:X} more than max of 0xFF", search_val);
                return 1;
            }

            search_vals_dec.push_back(search_val);

            auto it = find(bytes.begin() + start, bytes.end(), search_val);
            uint64_t skip{};
            while(it != bytes.end()) {
                it = find(bytes.begin() + start + skip, bytes.end(), search_val);

                if (it == bytes.end()) {
                    break;
                }

                locs[search_val].push_back(it - bytes.begin());
                skip = it - bytes.begin() + 1;
            }
            spdlog::info("Found {} locations for value 0x{:X}", locs[search_val].size(), search_val);
        }

        auto &first_search_val_locs = locs[search_vals_dec[0]];
        for(auto loc : first_search_val_locs) {
            spdlog::info("Finding locs within distance for (0x{:X}, 0x{:X})", bytes[loc], loc);
            vector<vector<uint64_t>> found_sub_locs_within_distance{};
            found_sub_locs_within_distance.push_back(vector<uint64_t>{loc});
            for(uint64_t i = 1; i < search_vals_dec.size(); i++) {
                auto &vec = found_sub_locs_within_distance.emplace_back();
                for(auto l : locs[search_vals_dec[i]]) {
                    if((l < loc && loc - l > distance) || (l > loc && l - loc > distance)) {
                        continue;
                    }

                    vec.push_back(l);
                }
            }

            if(found_sub_locs_within_distance.size() != locs.size()) {
                spdlog::info("err? {} {}", found_sub_locs_within_distance.size(), locs.size());
                continue;
            }

            auto cart_product = cartesian_product(found_sub_locs_within_distance);

            if(cart_product.size() > 8) {
                spdlog::info("Cartesian product too big {}", cart_product.size());
                continue;
            }

            for(const auto &loc_pair : cart_product) {
                std::string out{};
                fmt::format_to(std::back_inserter(out), "set found: (0x{:X}, 0x{:X})", bytes[loc_pair[0]], loc_pair[0]);
                for(uint64_t i = 1; i < loc_pair.size(); i++) {
                    fmt::format_to(std::back_inserter(out), ", (0x{:X}, 0x{:X})", bytes[loc_pair[i]], loc_pair[i]);
                }
                spdlog::info(out);
            }
        }

        return 0;
    }

    if((start_address.empty() && start_address_dec.empty()) || (end_address.empty() && end_address_dec.empty())) {
        spdlog::error("input, output, mode, start and end are mandatory arguments. e.g. ./snes-rom-corruptor -i rom.sfc -o corrupt_rom.sfc -m up -s 8000 -e 10000");
        spdlog::error("'{}', '{}', '{}', '{}', '{}'", input_file, output_file, mode, start_address, end_address);
        return 1;
    }

    uint64_t start{};
    uint64_t end{};
    {
        stringstream stream;
        if(!start_address.empty()) {
            stream << start_address;
            stream >> std::hex >> start;
        } else {
            stream << start_address_dec;
            stream >> start;
        }
    }

    {
        stringstream stream;
        if(!end_address.empty()) {
            stream << end_address;
            stream >> std::hex >> end;
        } else {
            stream << end_address_dec;
            stream >> end;
        }
    }

    if(!val.empty()) {
        stringstream stream;
        stream << val;
        stream >> std::hex >> val_dec;
    }

    spdlog::info("Corrupting addresses [0x{:X},0x{:X}) in mode {} value 0x{:X}", start, end, mode, val_dec);

    if(end < start) {
        spdlog::error("End address has to be higher or equal than start address");
        return 1;
    }

    if(end < 0 || start < 0) {
        spdlog::error("both end and start have to be positive");
        return 1;
    }

    ifstream input(input_file, ios::binary);
    ofstream output(output_file, ios::binary | ios::trunc);

    vector<char> bytes{istreambuf_iterator<char>(input), istreambuf_iterator<char>()};

    if(bytes.size() < end) {
        spdlog::error("rom size 0x{:X} less than 0x{:X}, corrupt rom maybe?", bytes.size(), end);
        return 1;
    }

    if (mode == "up") {
        for(uint64_t i = start; i < end; i++) {
            bytes[i] += val_dec;
        }
    } else if (mode == "down") {
        for(uint64_t i = start; i < end; i++) {
            bytes[i] -= val_dec;
        }
    } else if (mode == "set") {
        for(uint64_t i = start; i < end; i++) {
            bytes[i] = val_dec;
        }
    }

    copy(bytes.begin(), bytes.end(), ostreambuf_iterator<char>(output));

    return 0;
}
