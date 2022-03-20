#include <fstream>
#include <iterator>
#include <algorithm>
#include <lyra/lyra.hpp>
#include <spdlog/spdlog.h>
#include <vector>

using namespace std;

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
    uint32_t val{};

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
                ["-v"]["--value"]("Value in decimal to set bytes to in mode 'set'").required()
               | lyra::opt(mode, "mode")
                ["-m"]["--mode"]("Which mode to use to corrupt: 'up' to modify bytes up by 1, 'down' to modify bytes down by 1").required();

    cli.add_argument(lyra::help(help));

    auto result = cli.parse({argc, argv});

    if(help) {
        std::cout << cli;
        return 0;
    }

    if(!result) {
        spdlog::error("Error in command line: {}", result.message());
        return 1;
    }

    if((start_address.empty() && start_address_dec.empty()) || (end_address.empty() && end_address_dec.empty())) {
        spdlog::error("input, output, mode, start and end are mandatory arguments. e.g. ./snes-rom-corruptor -i rom.sfc -o corrupt_rom.sfc -m up -s 8000 -e 10000");
        spdlog::error("'{}', '{}', '{}', '{}', '{}'", input_file, output_file, mode, start_address, end_address);
        return 1;
    }

    if(mode != "up" && mode != "up2" && mode != "down" && mode != "set") {
        spdlog::error("mode '{}' unsupported. Supported modes: 'up', 'up2', 'down', 'set'", mode);
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

    spdlog::info("Corrupting addresses [0x{:X},0x{:X}) in mode {} value 0x{:X}", start, end, mode, val);

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
            bytes[i] += val;
        }
    } else if (mode == "down") {
        for(uint64_t i = start; i < end; i++) {
            bytes[i] -= val;
        }
    } else if (mode == "set") {
        for(uint64_t i = start; i < end; i++) {
            bytes[i] = val;
        }
    }

    copy(bytes.begin(), bytes.end(), ostreambuf_iterator<char>(output));

    return 0;
}